# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MacOS Sandbox (başlangıçta Seatbelt olarak adlandırılıyordu), **sandbox içinde çalışan uygulamaları**, uygulamanın çalıştığı **Sandbox profile içinde belirtilen izin verilen eylemlerle sınırlar**. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

**`com.apple.security.app-sandbox` entitlement'ına** sahip tüm uygulamalar Sandbox içinde çalıştırılır. **Apple binary'leri** genellikle bir Sandbox içinde çalıştırılır ve **App Store'daki tüm uygulamalar bu entitlement'a sahiptir**. Bu nedenle birçok uygulama Sandbox içinde çalıştırılır.<sup>[[4]](#references)</sup>

Bir process'in yapabileceği veya yapamayacağı işlemleri kontrol etmek için **Sandbox, MACF kullanarak** bir process'in gerçekleştirmeyi deneyebileceği neredeyse tüm işlemlerde (çoğu syscall dahil) **hook'lara sahiptir**. Ancak, uygulamanın **entitlement'larına** **bağlı olarak** Sandbox process'e karşı daha izin verici olabilir.

Sandbox'ın bazı önemli bileşenleri şunlardır:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userland'de çalışan bir **daemon** `/usr/libexec/sandboxd`
- **container'lar** `~/Library/Containers`

### Container'lar

Sandbox'a alınan her uygulamanın `~/Library/Containers/{CFBundleIdentifier}` içinde kendi container'ı olur:
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
Her bundle id klasörünün içinde, Home klasörünü taklit eden bir yapıyla App’in **plist** dosyasını ve **Data directory**’sini bulabilirsiniz:
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
> Symlink'ler Sandbox'tan "kaçmak" ve diğer klasörlere erişmek için mevcut olsa bile App'in bunlara erişmek için **izinlere** sahip olması gerekir. Bu izinler **`RedirectablePaths`** içindeki **`.plist`** dosyasında bulunur.

**`SandboxProfileData`**, derlenmiş sandbox profilinin B64'e dönüştürülmüş CFData'sıdır.
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
> Bir Sandbox application tarafından oluşturulan/değiştirilen her şey **quarantine attribute** alır. Bu, sandbox application **`open`** ile bir şey çalıştırmayı denerse Gatekeeper'ı tetikleyerek bir sandbox alanını engeller.

## Sandbox Profiles

Sandbox profilleri, hangi işlemlerin bu **Sandbox** içinde **izin verileceğini/engelleneceğini** belirten configuration dosyalarıdır. [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programming language kullanan **Sandbox Profile Language (SBPL)**'ı kullanır.

Burada bir örnek bulabilirsiniz:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> Hangi eylemlere izin verilebileceğini veya verilemeyeceğini görmek için bu [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) çalışmasına göz atın.<sup>[[5]](#references)</sup>
>
> Bir profile ait derlenmiş sürümde, işlemlerin adlarının dylib ve kext tarafından bilinen bir dizideki girdileriyle değiştirildiğini; bunun da derlenmiş sürümü daha kısa ve okunması daha zor hâle getirdiğini unutmayın.

`mdnsresponder` service gibi önemli **system services** de kendi özel **sandbox** ortamlarında çalışır. Bu özel **sandbox profiles** ortamlarını şu konumlarda görüntüleyebilirsiniz:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Diğer sandbox profiles şu adreste incelenebilir: [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- iOS'ta platform profile, binary içindeki `_platform_profile_data` içerisinde bulunan sandbox `.kext` dosyasının içindedir.

**App Store** uygulamaları **`/System/Library/Sandbox/Profiles/application.sb`** **profile** dosyasını kullanır. Bu profile içinde **`com.apple.security.network.server`** gibi entitlements değerlerinin bir process'in network kullanmasına nasıl izin verdiğini kontrol edebilirsiniz.

Daha sonra bazı **Apple daemon services**, `/System/Library/Sandbox/Profiles/*.sb` veya `/usr/share/sandbox/*.sb` konumlarında bulunan farklı profiles dosyalarını kullanır. Bu sandbox'lar, `sandbox_init_XXX` API'sini çağıran main function içinde uygulanır.<sup>[[3]](#references)</sup>

**SIP**, `/System/Library/Sandbox/rootless.conf` içindeki platform_profile adlı bir Sandbox profile'dır.

### Sandbox Profile Examples

Bir application'ı **specific sandbox profile** ile başlatmak için şunu kullanabilirsiniz:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> Windows üzerinde çalışan **Apple tarafından geliştirilen** **software** ürünlerinde application sandboxing gibi **ek güvenlik önlemleri** bulunmadığını unutmayın.

Bypass örnekleri:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sandbox dışında adı `~$` ile başlayan dosyalar yazabiliyorlar).<sup>[[7]](#references)</sup>

### Sandbox Tracing

#### Profil aracılığıyla

Sandbox'ın her action kontrol edildiğinde gerçekleştirdiği tüm kontrolleri trace etmek mümkündür. Bunun için aşağıdaki profili oluşturun:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Ve ardından bu profili kullanarak bir şey çalıştırın:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` içinde, gerçekleştirilen her sandbox kontrolünü her çağrıldığında görebilirsiniz (dolayısıyla çok sayıda duplicate bulunur).

Sandbox'ı **`-t`** parametresini kullanarak trace etmek de mümkündür: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API üzerinden

`libsystem_sandbox.dylib` tarafından export edilen `sandbox_set_trace_path` function'ı, sandbox kontrollerinin yazılacağı bir trace filename belirtmeye olanak tanır.\
`Sandbox` ile benzer bir işlem yapmak için `sandbox_vtrace_enable()` çağrılabilir ve ardından buffer'daki error log'ları `sandbox_vtrace_report()` çağrılarak alınabilir.

### Sandbox İncelemesi

`libsandbox.dylib`, bir process'in sandbox state'inin (extensions dahil) listesini sağlayan `sandbox_inspect_pid` adlı bir function export eder. Ancak bu function'ı yalnızca platform binary'leri kullanabilir.

### MacOS ve iOS Sandbox Profilleri

MacOS, system sandbox profillerini iki konumda depolar: **/usr/share/sandbox/** ve **/System/Library/Sandbox/Profiles**.

Ayrıca, bir third-party application _**com.apple.security.app-sandbox**_ entitlement'ını taşıyorsa system, o process'e **/System/Library/Sandbox/Profiles/application.sb** profilini uygular.

iOS'ta default profile'ın adı **container**'dır ve SBPL text representation'ına sahip değiliz. Memory'de bu sandbox, sandbox'taki her permission için Allow/Deny binary tree olarak temsil edilir.

### App Store uygulamalarında Custom SBPL

Şirketlerin uygulamalarını **custom Sandbox profilleriyle** (default profile yerine) çalıştırması mümkün olabilir. Bunun için Apple tarafından authorize edilmesi gereken **`com.apple.security.temporary-exception.sbpl`** entitlement'ını kullanmaları gerekir.

Bu entitlement'ın tanımını **`/System/Library/Sandbox/Profiles/application.sb:`** içinde kontrol etmek mümkündür.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Bu, **bu entitlement’tan sonraki string’i** bir Sandbox profili olarak **eval eder**.

### Sandbox Profilini Derleme ve Tersine Çevirme

**`sandbox-exec`** aracı, `libsandbox.dylib` içindeki `sandbox_compile_*` fonksiyonlarını kullanır. Dışa aktarılan başlıca fonksiyonlar şunlardır: `sandbox_compile_file` (bir dosya yolu bekler, `-f` parametresi), `sandbox_compile_string` (bir string bekler, `-p` parametresi), `sandbox_compile_name` (bir container adı bekler, `-n` parametresi), `sandbox_compile_entitlements` (entitlements plist’i bekler).

Bu tersine çevrilmiş ve [**sandbox-exec aracının open source sürümü**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c), **`sandbox-exec`** aracının derlenmiş Sandbox profilini bir dosyaya yazmasını sağlar.

Ayrıca, bir süreci bir container içinde kısıtlamak için `sandbox_spawnattrs_set[container/profilename]` çağrılabilir ve bir container veya önceden var olan profil aktarılabilir.

## Debug ve Sandbox Bypass

macOS’ta, süreçlerin kernel tarafından başlangıçtan itibaren sandbox’a alındığı iOS’un aksine, **süreçlerin Sandbox’a kendilerinin opt-in olması gerekir**. Bu, macOS’ta bir sürecin aktif olarak Sandbox’a girmeye karar verene kadar Sandbox tarafından kısıtlanmadığı anlamına gelir; ancak App Store uygulamaları her zaman sandbox’a alınır.

Süreçler, `com.apple.security.app-sandbox` entitlement’ına sahiplerse userland’den başlatıldıkları anda otomatik olarak Sandbox’a alınır. Bu sürecin ayrıntılı açıklaması için şuraya bakın:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions, bir objeye ek ayrıcalıklar vermeyi sağlar ve aşağıdaki fonksiyonlardan biri çağrılarak verilir:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions, süreç credentials’ından erişilebilen ikinci MACF label slot’unda saklanır. Aşağıdaki **`sbtool`** bu bilgilere erişebilir.

Extensions’ın genellikle izin verilen süreçler tarafından verildiğini unutmayın; örneğin `tccd`, bir süreç fotoğraflara erişmeye çalıştığında ve bu erişime bir XPC mesajı üzerinden izin verildiğinde `com.apple.tcc.kTCCServicePhotos` extension token’ını verir. Ardından süreç, extension token’ını tüketerek kendisine eklenmesini sağlamalıdır.\
Extension token’larının, verilen izinleri kodlayan uzun hexadecimal değerler olduğunu unutmayın. Ancak izin verilen PID’yi hardcoded olarak içermemeleri, token’a erişimi olan herhangi bir sürecin bunları **birden fazla süreç tarafından tüketilebilmesi** anlamına gelir.

Extensions’ın entitlements ile de yakından ilişkili olduğunu unutmayın; bu nedenle belirli entitlement’lara sahip olmak bazı extensions’ları otomatik olarak verebilir.

### **PID Ayrıcalıklarını Kontrol Etme**

[**Buna göre**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** fonksiyonları (bir `__mac_syscall`’dır), belirli bir PID, audit token veya unique ID için **bir işlemin Sandbox tarafından izin verilip verilmediğini** kontrol edebilir.<sup>[[8]](#references)</sup>

[**`sbtool` aracı**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (derlenmiş hâlini [burada](https://newosxbook.com/articles/hitsb.html) bulabilirsiniz), bir PID’nin belirli bir işlemi gerçekleştirip gerçekleştiremeyeceğini kontrol edebilir:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` içindeki `sandbox_suspend` ve `sandbox_unsuspend` fonksiyonlarını kullanarak sandbox'ı suspend ve unsuspend etmek de mümkündür.

Suspend fonksiyonunu çağırmak için, çağıranı bu fonksiyonu çağırma yetkisine sahip olarak doğrulamak amacıyla bazı entitlements'ın kontrol edildiğini unutmayın:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Bu system call (#381), önce çalıştırılacak modülü belirten bir string ilk argümanı, ardından çalıştırılacak fonksiyonu belirten bir code ikinci argümanı bekler. Üçüncü argüman ise çalıştırılan fonksiyona bağlıdır.<sup>[[2]](#references)</sup>

`___sandbox_ms` fonksiyonu, ilk argümanda `"Sandbox"` belirterek `mac_syscall` çağrısını wrap eder; tıpkı `___sandbox_msp`'nin `mac_set_proc` (#387) için bir wrapper olması gibi. Ardından, `___sandbox_ms` tarafından desteklenen code'lardan bazıları bu tabloda bulunabilir:

- **set_profile (#0)**: Bir process'e derlenmiş veya adlandırılmış bir profile uygular.
- **platform_policy (#1)**: Platforma özgü policy kontrollerini uygular (macOS ve iOS arasında değişir).
- **check_sandbox (#2)**: Belirli bir sandbox operation için manuel kontrol gerçekleştirir.
- **note (#3)**: Bir Sandbox'a annotation ekler.
- **container (#4)**: Genellikle debugging veya tanımlama amacıyla bir sandbox'a annotation ekler.
- **extension_issue (#5)**: Bir process için yeni bir extension oluşturur.
- **extension_consume (#6)**: Belirtilen bir extension'ı kullanır.
- **extension_release (#7)**: Kullanılmış bir extension'a bağlı memory'yi serbest bırakır.
- **extension_update_file (#8)**: Sandbox içindeki mevcut bir file extension'ın parametrelerini değiştirir.
- **extension_twiddle (#9)**: Mevcut bir file extension'ı ayarlar veya değiştirir (ör. TextEdit, rtf, rtfd).
- **suspend (#10)**: Tüm sandbox kontrollerini geçici olarak suspend eder (uygun entitlements gerektirir).
- **unsuspend (#11)**: Daha önce suspend edilmiş tüm sandbox kontrollerini yeniden başlatır.
- **passthrough_access (#12)**: Sandbox kontrollerini bypass ederek bir kaynağa doğrudan passthrough erişimine izin verir.
- **set_container_path (#13)**: (Yalnızca iOS) Bir app group veya signing ID için container path ayarlar.
- **container_map (#14)**: `containermanagerd` üzerinden bir container path alır.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Sandbox içinde user mode metadata'sı ayarlar.
- **inspect (#16)**: Sandbox'a alınmış bir process hakkında debug bilgisi sağlar.
- **dump (#18)**: (macOS 11) Analiz için bir sandbox'ın mevcut profile'ını dump eder.
- **vtrace (#19)**: Monitoring veya debugging amacıyla sandbox operation'larını trace eder.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Adlandırılmış profile'ları devre dışı bırakır (ör. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Tek bir çağrıda birden fazla `sandbox_check` operation'ı gerçekleştirir.
- **reference_retain_by_audit_token (#28)**: Sandbox kontrollerinde kullanılmak üzere bir audit token için reference oluşturur.
- **reference_release (#29)**: Daha önce retain edilmiş bir audit token reference'ını serbest bırakır.
- **rootless_allows_task_for_pid (#30)**: `task_for_pid` işlemine izin verilip verilmediğini doğrular (`csr` kontrollerine benzer).
- **rootless_whitelist_push (#31)**: (macOS) Bir System Integrity Protection (SIP) manifest file'ını uygular.
- **rootless_whitelist_check (preflight) (#32)**: SIP manifest file'ını execution öncesinde kontrol eder.
- **rootless_protected_volume (#33)**: (macOS) SIP protections'larını bir disk veya partition'a uygular.
- **rootless_mkdir_protected (#34)**: SIP/DataVault protection'ını bir directory oluşturma işlemine uygular.

## Sandbox.kext

iOS'ta kernel extension'ın, değiştirilmelerini önlemek amacıyla tüm profile'ları `__TEXT.__const` segment'inde **hardcoded** olarak içerdiğini unutmayın. Kernel extension içindeki bazı ilginç fonksiyonlar şunlardır:

- **`hook_policy_init`**: `mpo_policy_init` fonksiyonunu hook'lar ve `mac_policy_register` sonrasında çağrılır. Sandbox'ın initialization işlemlerinin çoğunu gerçekleştirir. Ayrıca SIP'yi initialize eder.
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` ve (`PE_i_can_has_debugger` ile boot edilmişse) `security.mac.sandbox.debug_mode` değerlerini register ederek sysctl interface'ini ayarlar.
- **`hook_policy_syscall`**: İlk argüman olarak `"Sandbox"` ve ikinci argümanda operation'ı belirten code ile `mac_syscall` tarafından çağrılır. İstenen code'a göre çalıştırılacak code'u bulmak için bir switch kullanılır.

### MACF Hooks

**`Sandbox.kext`**, MACF aracılığıyla yüzden fazla hook kullanır. Hook'ların çoğu, action'ın gerçekleştirilmesine izin veren bazı basit durumları kontrol eder; aksi durumda MACF'den alınan **credentials**, gerçekleştirilecek **operation**'a karşılık gelen bir number ve output için bir **buffer** ile **`cred_sb_evalutate`** fonksiyonunu çağırırlar.<sup>[[1]](#references)</sup>

Buna iyi bir örnek, `mmap` fonksiyonunu hook'layan **`_mpo_file_check_mmap`** fonksiyonudur. Bu fonksiyon öncelikle yeni memory'nin writable olup olmadığını kontrol eder (writable değilse execution'a izin verir), ardından bunun dyld shared cache için kullanılıp kullanılmadığını kontrol eder ve kullanılıyorsa execution'a izin verir; son olarak daha ileri allowance kontrolleri gerçekleştirmek için **`sb_evaluate_internal`** (veya wrapper'larından birini) çağırır.

Bununla birlikte, Sandbox'ın kullandığı yüzlerce hook arasından özellikle ilgi çekici 3 hook vardır:

- `mpo_proc_check_for`: Gerekliyse ve daha önce uygulanmamışsa profile'ı uygular.
- `mpo_vnode_check_exec`: Bir process ilgili binary'yi yüklediğinde çağrılır; ardından bir profile kontrolü ve SUID/SGID execution'larını yasaklayan bir kontrol gerçekleştirilir.
- `mpo_cred_label_update_execve`: Label atandığında çağrılır. Binary tamamen yüklenmiş ancak henüz execute edilmemişken çağrıldığı için en uzun olanıdır. Sandbox object'i oluşturmak, sandbox struct'ını kauth credentials'a attach etmek, mach port'larına erişimi kaldırmak gibi işlemler gerçekleştirir.

**`_cred_sb_evalutate`** fonksiyonunun **`sb_evaluate_internal`** üzerinde bir wrapper olduğunu unutmayın. Bu fonksiyon, kendisine aktarılan credentials'ı alır ve ardından genellikle varsayılan olarak tüm process'lere uygulanan **platform profile**'ını ve sonra da **specific process profile**'ını değerlendiren **`eval`** fonksiyonunu kullanarak evaluation gerçekleştirir. Platform profile'ının macOS'taki **SIP**'nin temel bileşenlerinden biri olduğunu unutmayın.

## Sandboxd

Sandbox ayrıca `com.apple.sandboxd` XPC Mach service'ini expose eden ve kernel extension'ın iletişim kurmak için kullandığı özel port 14'ü (`HOST_SEATBELT_PORT`) bind eden bir user daemon çalıştırır. MIG kullanarak bazı fonksiyonları expose eder.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
