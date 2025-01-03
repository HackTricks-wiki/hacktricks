# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MacOS Sandbox (ilk olarak Seatbelt olarak adlandırılmıştır) **sandbox içinde çalışan uygulamaları** **uygulamanın çalıştığı Sandbox profilinde belirtilen izin verilen eylemlerle** sınırlar. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

**`com.apple.security.app-sandbox`** **yetkisine** sahip herhangi bir uygulama sandbox içinde çalıştırılacaktır. **Apple ikili dosyaları** genellikle bir Sandbox içinde çalıştırılır ve **App Store'dan gelen tüm uygulamalar bu yetkiye sahiptir**. Bu nedenle, birçok uygulama sandbox içinde çalıştırılacaktır.

Bir sürecin ne yapabileceğini veya ne yapamayacağını kontrol etmek için **Sandbox, bir sürecin denemesi olası olan hemen hemen her işlemde** **MACF** kullanarak **kancalara** sahiptir. Ancak, uygulamanın **yetkilerine** bağlı olarak Sandbox, süreçle daha hoşgörülü olabilir.

Sandbox'ın bazı önemli bileşenleri şunlardır:

- **kernel uzantısı** `/System/Library/Extensions/Sandbox.kext`
- **özel çerçeve** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Kullanıcı alanında çalışan bir **daemon** `/usr/libexec/sandboxd`
- **kapsayıcılar** `~/Library/Containers`

### Kapsayıcılar

Her sandbox'lanmış uygulamanın `~/Library/Containers/{CFBundleIdentifier}` içinde kendi kapsayıcısı olacaktır:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Her bir bundle id klasörünün içinde, Home klasörünü taklit eden bir yapıya sahip **plist** ve uygulamanın **Data dizini** bulunabilir:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Symlinklerin Sandbox'tan "kaçmak" ve diğer klasörlere erişmek için orada olduğunu unutmayın, ancak Uygulamanın yine de onlara erişim için **izinlere sahip olması** gerekir. Bu izinler, `RedirectablePaths` içindeki **`.plist`** dosyasındadır.

**`SandboxProfileData`**, B64'e kaçırılmış derlenmiş sandbox profil CFData'dır.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Sandbox uygulaması tarafından oluşturulan/değiştirilen her şey **karantina niteliği** alacaktır. Bu, sandbox uygulaması bir şeyi **`open`** ile çalıştırmaya çalıştığında Gatekeeper'ı tetikleyerek bir sandbox alanını engelleyecektir.

## Sandbox Profilleri

Sandbox profilleri, o **Sandbox** içinde neyin **izin verileceğini/yasaklanacağını** belirten yapılandırma dosyalarıdır. **Sandbox Profil Dili (SBPL)** kullanır ve bu dil [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programlama dilini temel alır.

Burada bir örnek bulabilirsiniz:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Daha fazla izin verilebilecek veya reddedilebilecek eylemleri kontrol etmek için bu [**araştırmaya**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **bakın.**
>
> Bir profilin derlenmiş versiyonunda, işlemlerin adları, dylib ve kext tarafından bilinen bir dizideki girişleriyle değiştirilir, bu da derlenmiş versiyonu daha kısa ve okunması daha zor hale getirir.

Önemli **sistem hizmetleri** ayrıca `mdnsresponder` hizmeti gibi kendi özel **sandbox**'larında çalışır. Bu özel **sandbox profillerini** şu dizinlerde görebilirsiniz:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Diğer sandbox profilleri [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) adresinde kontrol edilebilir.

**App Store** uygulamaları **`/System/Library/Sandbox/Profiles/application.sb`** **profilini** kullanır. Bu profilde **`com.apple.security.network.server`** gibi yetkilendirmelerin bir sürecin ağı kullanmasına nasıl izin verdiğini kontrol edebilirsiniz.

Daha sonra, bazı **Apple daemon hizmetleri** `/System/Library/Sandbox/Profiles/*.sb` veya `/usr/share/sandbox/*.sb` dizinlerinde bulunan farklı profilleri kullanır. Bu sandbox'lar, `sandbox_init_XXX` API'sini çağıran ana işlevde uygulanır.

**SIP**, `/System/Library/Sandbox/rootless.conf` içinde platform_profile olarak adlandırılan bir Sandbox profilidir.

### Sandbox Profil Örnekleri

Belirli bir **sandbox profili** ile bir uygulamayı başlatmak için şunu kullanabilirsiniz:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> **Apple tarafından yazılmış** **yazılım** **Windows** üzerinde **ek güvenlik önlemlerine** sahip değildir, örneğin uygulama sandboxing.

Atlatma örnekleri:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sandbox dışına `~$` ile başlayan dosyalar yazabiliyorlar).

### Sandbox İzleme

#### Profil aracılığıyla

Her eylem kontrol edildiğinde sandbox'ın gerçekleştirdiği tüm kontrolleri izlemek mümkündür. Bunun için sadece aşağıdaki profili oluşturun:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Ve ardından o profili kullanarak bir şey çalıştırın:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` dosyasında, her çağrıldığında gerçekleştirilen her sandbox kontrolünü görebileceksiniz (yani, birçok tekrar).

Ayrıca, sandbox'ı **`-t`** parametresi ile izlemek de mümkündür: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API Üzerinden

`libsystem_sandbox.dylib` tarafından dışa aktarılan `sandbox_set_trace_path` fonksiyonu, sandbox kontrollerinin yazılacağı bir izleme dosya adı belirtmeye olanak tanır.\
Ayrıca, `sandbox_vtrace_enable()` çağrılarak benzer bir şey yapmak ve ardından `sandbox_vtrace_report()` çağrısı ile hata günlüklerini almak da mümkündür.

### Sandbox İncelemesi

`libsandbox.dylib`, bir işlemin sandbox durumunun (uzantılar dahil) bir listesini veren sandbox_inspect_pid adlı bir fonksiyon dışa aktarmaktadır. Ancak, yalnızca platform ikili dosyaları bu fonksiyonu kullanabilir.

### MacOS & iOS Sandbox Profilleri

MacOS, sistem sandbox profillerini iki konumda saklar: **/usr/share/sandbox/** ve **/System/Library/Sandbox/Profiles**.

Ve eğer bir üçüncü taraf uygulaması _**com.apple.security.app-sandbox**_ yetkisini taşıyorsa, sistem bu işlemi **/System/Library/Sandbox/Profiles/application.sb** profili ile uygular.

iOS'ta, varsayılan profil **container** olarak adlandırılır ve SBPL metin temsiline sahip değiliz. Bellekte, bu sandbox, sandbox'tan her izin için Allow/Deny ikili ağacı olarak temsil edilir.

### App Store uygulamalarında Özel SBPL

Şirketlerin uygulamalarını **özel Sandbox profilleri ile** çalıştırmaları mümkün olabilir (varsayılan olan yerine). Bunun için **`com.apple.security.temporary-exception.sbpl`** yetkisini kullanmaları gerekir ve bu yetki Apple tarafından yetkilendirilmelidir.

Bu yetkinin tanımını **`/System/Library/Sandbox/Profiles/application.sb:`** dosyasında kontrol etmek mümkündür.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Bu, **bu yetki sonrasında dizeyi değerlendirir** bir Sandbox profili olarak.

### Sandbox Profili Derleme ve Çözme

**`sandbox-exec`** aracı, `libsandbox.dylib`'den `sandbox_compile_*` fonksiyonlarını kullanır. İhracat edilen ana fonksiyonlar şunlardır: `sandbox_compile_file` (bir dosya yolu bekler, parametre `-f`), `sandbox_compile_string` (bir dize bekler, parametre `-p`), `sandbox_compile_name` (bir konteyner adı bekler, parametre `-n`), `sandbox_compile_entitlements` (yetki plist'ini bekler).

Bu tersine çevrilmiş ve [**sandbox-exec aracının açık kaynaklı versiyonu**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c), **`sandbox-exec`** aracının derlenmiş sandbox profilini bir dosyaya yazmasına olanak tanır.

Ayrıca, bir süreci bir konteyner içinde sınırlamak için `sandbox_spawnattrs_set[container/profilename]` çağrılabilir ve bir konteyner veya önceden var olan bir profil geçilebilir.

## Sandbox'ı Hata Ayıklama ve Aşma

macOS'ta, süreçlerin başlangıçta çekirdek tarafından sandbox'a alındığı iOS'un aksine, **süreçlerin kendilerinin sandbox'a katılması gerekir**. Bu, macOS'ta bir sürecin, aktif olarak girmeye karar vermediği sürece sandbox tarafından kısıtlanmadığı anlamına gelir, ancak App Store uygulamaları her zaman sandbox'a alınır.

Süreçler, `com.apple.security.app-sandbox` yetkisine sahip olduklarında kullanıcı alanından otomatik olarak Sandbox'a alınır. Bu sürecin ayrıntılı açıklaması için kontrol edin:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Uzantıları**

Uzantılar, bir nesneye daha fazla ayrıcalık vermeye olanak tanır ve aşağıdaki fonksiyonlardan birini çağırarak verilir:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Uzantılar, süreç kimlik bilgileri üzerinden erişilebilen ikinci MACF etiket slotunda saklanır. Aşağıdaki **`sbtool`** bu bilgilere erişebilir.

Uzantıların genellikle izin verilen süreçler tarafından verildiğini unutmayın; örneğin, `tccd`, bir sürecin fotoğraflara erişmeye çalıştığında ve bir XPC mesajında izin verildiğinde `com.apple.tcc.kTCCServicePhotos` uzantı token'ını verecektir. Ardından, sürecin uzantı token'ını tüketmesi gerekecek, böylece ona eklenir.\
Uzantı token'larının, verilen izinleri kodlayan uzun onaltılı sayılar olduğunu unutmayın. Ancak, izin verilen PID'nin sabit kodlu olmadığını belirtmek gerekir; bu, token'a erişimi olan herhangi bir sürecin **birden fazla süreç tarafından tüketilebileceği** anlamına gelir.

Uzantıların, yetkilerle de çok ilgili olduğunu unutmayın; bu nedenle belirli yetkilere sahip olmak, belirli uzantıları otomatik olarak verebilir.

### **PID Ayrıcalıklarını Kontrol Etme**

[**Buna göre**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** fonksiyonları (bu bir `__mac_syscall`), belirli bir PID, denetim token'ı veya benzersiz ID ile sandbox tarafından **bir işlemin izin verilip verilmediğini** kontrol edebilir.

[**sbtool aracı**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (bunu [burada derlenmiş olarak bulabilirsiniz](https://newosxbook.com/articles/hitsb.html)), bir PID'nin belirli eylemleri gerçekleştirip gerçekleştiremeyeceğini kontrol edebilir:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Sandbox'ı `libsystem_sandbox.dylib` içindeki `sandbox_suspend` ve `sandbox_unsuspend` fonksiyonları kullanarak askıya almak ve askıdan kaldırmak da mümkündür.

Askıya alma fonksiyonunu çağırmak için bazı yetkilendirmelerin kontrol edildiğini unutmayın, bu da çağıranın onu çağırmasına izin vermek içindir:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Bu sistem çağrısı (#381), çalıştırılacak modülü belirten birinci argüman olarak bir dize bekler ve ardından çalıştırılacak fonksiyonu belirten bir kodu ikinci argüman olarak alır. Üçüncü argüman ise yürütülen fonksiyona bağlı olacaktır.

`___sandbox_ms` çağrısı, birinci argümanda `"Sandbox"` belirterek `mac_syscall`'ı sarmalar, tıpkı `___sandbox_msp`'nin `mac_set_proc`'un (#387) bir sarmalayıcı olması gibi. Ardından, `___sandbox_ms` tarafından desteklenen bazı kodlar bu tabloda bulunabilir:

- **set_profile (#0)**: Bir işleme derlenmiş veya adlandırılmış bir profil uygular.
- **platform_policy (#1)**: Platforma özgü politika kontrollerini zorlar (macOS ve iOS arasında değişir).
- **check_sandbox (#2)**: Belirli bir sandbox işleminin manuel kontrolünü gerçekleştirir.
- **note (#3)**: Bir Sandbox'a not ekler.
- **container (#4)**: Genellikle hata ayıklama veya tanımlama için bir sandbox'a bir not ekler.
- **extension_issue (#5)**: Bir işlem için yeni bir uzantı oluşturur.
- **extension_consume (#6)**: Verilen bir uzantıyı tüketir.
- **extension_release (#7)**: Tüketilen bir uzantıya bağlı belleği serbest bırakır.
- **extension_update_file (#8)**: Sandbox içindeki mevcut bir dosya uzantısının parametrelerini değiştirir.
- **extension_twiddle (#9)**: Mevcut bir dosya uzantısını ayarlar veya değiştirir (örneğin, TextEdit, rtf, rtfd).
- **suspend (#10)**: Tüm sandbox kontrollerini geçici olarak askıya alır (uygun yetkilendirmeler gerektirir).
- **unsuspend (#11)**: Daha önce askıya alınan tüm sandbox kontrollerini yeniden başlatır.
- **passthrough_access (#12)**: Sandbox kontrollerini atlayarak bir kaynağa doğrudan geçiş erişimi sağlar.
- **set_container_path (#13)**: (sadece iOS) Bir uygulama grubu veya imza kimliği için bir konteyner yolu ayarlar.
- **container_map (#14)**: (sadece iOS) `containermanagerd`'en bir konteyner yolu alır.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Sandbox'ta kullanıcı modu meta verilerini ayarlar.
- **inspect (#16)**: Sandbox'lanmış bir işlem hakkında hata ayıklama bilgisi sağlar.
- **dump (#18)**: (macOS 11) Analiz için bir sandbox'ın mevcut profilini döker.
- **vtrace (#19)**: İzleme veya hata ayıklama için sandbox işlemlerini izler.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Adlandırılmış profilleri devre dışı bırakır (örneğin, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Tek bir çağrıda birden fazla `sandbox_check` işlemi gerçekleştirir.
- **reference_retain_by_audit_token (#28)**: Sandbox kontrollerinde kullanılmak üzere bir denetim belirteci için bir referans oluşturur.
- **reference_release (#29)**: Daha önce tutulan bir denetim belirteci referansını serbest bırakır.
- **rootless_allows_task_for_pid (#30)**: `task_for_pid`'in izinli olup olmadığını doğrular (benzer şekilde `csr` kontrolleri).
- **rootless_whitelist_push (#31)**: (macOS) Bir Sistem Bütünlüğü Koruma (SIP) manifest dosyası uygular.
- **rootless_whitelist_check (preflight) (#32)**: Uygulamadan önce SIP manifest dosyasını kontrol eder.
- **rootless_protected_volume (#33)**: (macOS) Bir disk veya bölüme SIP korumaları uygular.
- **rootless_mkdir_protected (#34)**: Bir dizin oluşturma işlemi için SIP/DataVault koruması uygular.

## Sandbox.kext

iOS'ta çekirdek uzantısının **tüm profilleri sabit kodlu** olarak `__TEXT.__const` segmentinde içerdiğini unutmayın, böylece bunların değiştirilmesi önlenir. Çekirdek uzantısından bazı ilginç fonksiyonlar şunlardır:

- **`hook_policy_init`**: `mpo_policy_init`'i bağlar ve `mac_policy_register`'dan sonra çağrılır. Sandbox'ın çoğu başlatmasını gerçekleştirir. Ayrıca SIP'yi de başlatır.
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` ve `security.mac.sandbox.debug_mode`'u kaydederek sysctl arayüzünü ayarlar (eğer `PE_i_can_has_debugger` ile başlatılmışsa).
- **`hook_policy_syscall`**: `mac_syscall` tarafından "Sandbox" birinci argüman olarak ve ikinci argümanda işlemi belirten kod ile çağrılır. İstenen koda göre çalıştırılacak kodu bulmak için bir switch kullanılır.

### MACF Hooks

**`Sandbox.kext`** MACF aracılığıyla yüzlerce kancadan fazlasını kullanır. Kancaların çoğu, eğer değilse, eylemi gerçekleştirmeye izin veren bazı önemsiz durumları kontrol eder, aksi takdirde **`cred_sb_evalutate`**'yi MACF'den alınan **kimlik bilgileri** ve gerçekleştirilecek **işlem** ile ilgili bir sayı ve **çıkış** için bir **tampon** ile çağırırlar.

Bunun iyi bir örneği, **`_mpo_file_check_mmap`** fonksiyonudur; bu fonksiyon **`mmap`**'i bağlar ve yeni belleğin yazılabilir olup olmadığını kontrol etmeye başlar (ve eğer değilse yürütmeye izin vermez), ardından bunun dyld paylaşılan önbelleği için kullanılıp kullanılmadığını kontrol eder ve eğer öyleyse yürütmeye izin verir, ve nihayetinde daha fazla izin kontrolü gerçekleştirmek için **`sb_evaluate_internal`**'i (veya onun sarmalayıcılarından birini) çağırır.

Ayrıca, Sandbox'ın kullandığı yüzlerce kancanın dışında, özellikle ilginç olan 3 kanca vardır:

- `mpo_proc_check_for`: Gerekirse profili uygular ve daha önce uygulanmadıysa.
- `mpo_vnode_check_exec`: Bir işlem ilişkili ikili dosyayı yüklediğinde çağrılır, ardından bir profil kontrolü gerçekleştirilir ve ayrıca SUID/SGID yürütmelerini yasaklayan bir kontrol yapılır.
- `mpo_cred_label_update_execve`: Etiket atandığında çağrılır. Bu, ikili dosya tamamen yüklendiğinde ancak henüz yürütülmediğinde çağrıldığı için en uzun olanıdır. Sandbox nesnesi oluşturma, kauth kimlik bilgilerine sandbox yapısını ekleme, mach portlarına erişimi kaldırma gibi işlemleri gerçekleştirir...

Unutmayın ki **`_cred_sb_evalutate`**, **`sb_evaluate_internal`**'in bir sarmalayıcısıdır ve bu fonksiyon, geçirilen kimlik bilgilerini alır ve ardından genellikle tüm işlemlere varsayılan olarak uygulanan **platform profili** ve ardından **belirli işlem profili** ile değerlendirme gerçekleştiren **`eval`** fonksiyonunu kullanarak değerlendirme yapar. Unutmayın ki platform profili, macOS'taki **SIP**'in ana bileşenlerinden biridir.

## Sandboxd

Sandbox ayrıca, XPC Mach servisi `com.apple.sandboxd`'yi sergileyen bir kullanıcı daemon'u çalıştırır ve çekirdek uzantısının iletişim kurmak için kullandığı özel port 14 (`HOST_SEATBELT_PORT`) ile bağlanır. MIG kullanarak bazı fonksiyonlar sunar.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
