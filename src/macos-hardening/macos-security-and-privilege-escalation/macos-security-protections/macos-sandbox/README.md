# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MacOS Sandbox (başlangıçta Seatbelt olarak adlandırılıyordu), sandbox içinde çalışan **uygulamaları**, uygulamanın çalıştığı Sandbox profilinde belirtilen **izin verilen eylemlerle** sınırlar. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

**`com.apple.security.app-sandbox`** **entitlement**'ına sahip tüm uygulamalar sandbox içinde çalıştırılır. **Apple binaries** genellikle bir Sandbox içinde çalıştırılır ve **App Store'daki tüm uygulamalar bu entitlement'a sahiptir**. Bu nedenle birçok uygulama sandbox içinde çalıştırılır.<sup>[[4]](#references)</sup>

Bir sürecin ne yapıp yapamayacağını kontrol etmek için **Sandbox**, **MACF** kullanarak bir sürecin gerçekleştirmeyi deneyebileceği neredeyse tüm işlemlerde (çoğu syscall dahil) **hook'lara sahiptir**. Ancak uygulamanın **entitlements**'ına **bağlı olarak** Sandbox, süreç konusunda daha izin verici olabilir.

Sandbox'ın bazı önemli bileşenleri şunlardır:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Kullanıcı alanında çalışan bir **daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Sandbox içindeki her uygulamanın `~/Library/Containers/{CFBundleIdentifier}` konumunda kendi container'ı bulunur:
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
Her bundle id klasörünün içinde, Home klasörünü taklit eden bir yapıya sahip Uygulamanın **plist** dosyasını ve **Data directory**'sini bulabilirsiniz:
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
> Sandbox'tan "kaçmak" ve diğer klasörlere erişmek için symlink'ler mevcut olsa bile App'in bunlara erişmek için **izinlere** sahip olması gerekir. Bu izinler **`RedirectablePaths`** içindeki **`.plist`** dosyasındadır.

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
> Bir Sandboxed uygulama tarafından oluşturulan/değiştirilen her şey **quarantine attribut**e sahip olur. Bu, sandbox uygulaması **`open`** kullanarak bir şeyi çalıştırmaya çalıştığında Gatekeeper'ı tetikleyerek bir sandbox alanını engeller.

## Sandbox Profiles

Sandbox profilleri, ilgili **Sandbox** içinde neye **izin verileceğini/neyin engelleneceğini** belirten yapılandırma dosyalarıdır. [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programlama dilini kullanan **Sandbox Profile Language (SBPL)** dilini kullanır.

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
> Daha fazla izin verilebilecek veya reddedilebilecek action'ı görmek için bu [**araştırmaya**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **bakın.**<sup>[[5]](#references)</sup>
>
> Bir profile'ın derlenmiş sürümünde operation'ların adlarının, dylib ve kext tarafından bilinen bir array'deki girdilerle değiştirildiğini; bunun da derlenmiş sürümü daha kısa ve okunması daha zor hâle getirdiğini unutmayın.

`mdnsresponder` servisi gibi önemli **system services** de kendi özel **sandbox**'ları içinde çalışır. Bu özel **sandbox profiles**'ları şuralarda görüntüleyebilirsiniz:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Diğer sandbox profilleri [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) adresinde incelenebilir.
- iOS'ta platform profile, binary içindeki `_platform_profile_data` içerisinde bulunan sandbox `.kext`'inin içindedir.

**App Store** uygulamaları **`/System/Library/Sandbox/Profiles/application.sb`** **profile**'ını kullanır. Bu profile'da **`com.apple.security.network.server`** gibi entitlement'ların bir process'in network'ü kullanmasına nasıl izin verdiğini görebilirsiniz.

Ardından bazı **Apple daemon services**, `/System/Library/Sandbox/Profiles/*.sb` veya `/usr/share/sandbox/*.sb` konumlarında bulunan farklı profile'ları kullanır. Bu sandbox'lar, `sandbox_init_XXX` API'sini çağıran ana function'da uygulanır.<sup>[[3]](#references)</sup>

**SIP**, `/System/Library/Sandbox/rootless.conf` içindeki platform_profile adlı bir Sandbox profile'ıdır.

### Sandbox Profile Examples

Bir uygulamayı **specific sandbox profile** ile başlatmak için şunu kullanabilirsiniz:
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
> Windows üzerinde çalışan **Apple-authored** **software**'ın, application sandboxing gibi **additional security precautions** içermediğini unutmayın.

Bypasses örnekleri:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (adı `~$` ile başlayan dosyaları sandbox dışına yazabiliyorlar).<sup>[[7]](#references)</sup>

### Sandbox Tracing

#### Profil aracılığıyla

sandbox'ın bir action her kontrol edildiğinde gerçekleştirdiği tüm check'leri trace etmek mümkündür. Bunun için aşağıdaki profile'ı oluşturmanız yeterlidir:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Ve ardından o profili kullanarak bir şey çalıştırın:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` içinde gerçekleştirilen her sandbox kontrolünü, her çağrıldığında görebilirsiniz (bu nedenle çok sayıda duplicate bulunur).

Sandbox'ı **`-t`** parametresiyle trace etmek de mümkündür: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API üzerinden

`libsystem_sandbox.dylib` tarafından export edilen `sandbox_set_trace_path` function'ı, sandbox kontrollerinin yazılacağı bir trace dosya adı belirtmenizi sağlar.\
Ayrıca `sandbox_vtrace_enable()` çağrılarak ve ardından buffer'daki error log'ları `sandbox_vtrace_report()` ile alınarak benzer bir işlem gerçekleştirilebilir.

### Sandbox Inspection

`libsandbox.dylib`, bir process'in sandbox durumunun (extensions dahil) listesini veren `sandbox_inspect_pid` adlı bir function export eder. Ancak bu function'ı yalnızca platform binaries kullanabilir.

### MacOS ve iOS Sandbox Profiles

MacOS, system sandbox profiles dosyalarını iki konumda saklar: **/usr/share/sandbox/** ve **/System/Library/Sandbox/Profiles**.

Üçüncü taraf bir application _**com.apple.security.app-sandbox**_ entitlement'ına sahipse system, **/System/Library/Sandbox/Profiles/application.sb** profile'ını bu process'e uygular.

iOS'ta default profile'ın adı **container**'dır ve SBPL text representation'ına sahip değiliz. Memory'de bu sandbox, sandbox'taki her permission için Allow/Deny binary tree olarak temsil edilir.

### App Store apps'te Custom SBPL

Şirketlerin app'lerini **custom Sandbox profiles** ile (default profile yerine) çalıştırmaları mümkün olabilir. Bunun için Apple tarafından authorize edilmesi gereken **`com.apple.security.temporary-exception.sbpl`** entitlement'ını kullanmaları gerekir.

Bu entitlement'ın tanımını **`/System/Library/Sandbox/Profiles/application.sb:`** içinde kontrol etmek mümkündür.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Bu, **bu entitlement'tan** sonra gelen string'i bir Sandbox profili olarak **eval** eder.

### Sandbox Profilini Derleme ve Decompile Etme

**`sandbox-exec`** aracı, `libsandbox.dylib` içindeki `sandbox_compile_*` fonksiyonlarını kullanır. Dışa aktarılan ana fonksiyonlar şunlardır: `sandbox_compile_file` (bir dosya yolu bekler, parametre `-f`), `sandbox_compile_string` (bir string bekler, parametre `-p`), `sandbox_compile_name` (bir container adı bekler, parametre `-n`), `sandbox_compile_entitlements` (entitlements plist bekler).

Bu reverse edilmiş ve [**open source hale getirilmiş sandbox-exec sürümü**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c), **`sandbox-exec`** aracının derlenmiş Sandbox profilini bir dosyaya yazmasını sağlar.

Ayrıca, bir process'i bir container içinde kısıtlamak için `sandbox_spawnattrs_set[container/profilename]` çağrılabilir ve bir container veya önceden var olan bir profil geçirilebilir.

## Debug ve Bypass Sandbox

macOS'ta, process'lerin başlangıçtan itibaren kernel tarafından sandbox'landığı iOS'un aksine, **process'ler Sandbox'a kendileri opt-in yapmak zorundadır**. Bu, macOS'ta bir process aktif olarak Sandbox'a girmeye karar verene kadar Sandbox tarafından kısıtlanmadığı anlamına gelir; ancak App Store uygulamaları her zaman sandbox'lanır.

Process'ler `com.apple.security.app-sandbox` entitlement'ına sahip olduklarında userland'den başlatılırken otomatik olarak Sandbox'lanır. Bu sürecin ayrıntılı açıklaması için şuraya bakın:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions, bir objeye ek ayrıcalıklar verilmesini sağlar ve aşağıdaki fonksiyonlardan biri çağrılarak verilir:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions, process credentials içinden erişilebilen ikinci MACF label slot'unda depolanır. Aşağıdaki **`sbtool`** bu bilgilere erişebilir.

Extensions genellikle izin verilen process'ler tarafından verilir; örneğin `tccd`, bir process fotoğraflara erişmeye çalıştığında ve bir XPC mesajında erişimine izin verildiğinde `com.apple.tcc.kTCCServicePhotos` extension token'ını verir. Ardından process'in, extension token'ını tüketmesi gerekir; böylece token kendisine eklenir.\
Extension token'larının, verilen izinleri encode eden uzun hexadecimal değerler olduğunu unutmayın. Ancak izin verilen PID'yi hardcode edilmiş şekilde içermemeleri, token'a erişimi olan herhangi bir process'in token'ı **birden fazla process tarafından tüketebilmesi** anlamına gelir.

Extensions'ın entitlements ile de yakından ilişkili olduğunu unutmayın; dolayısıyla belirli entitlements'a sahip olmak bazı extensions'ları otomatik olarak verebilir.

### **PID Ayrıcalıklarını Kontrol Etme**

[**Buna göre**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** fonksiyonları (bir `__mac_syscall`'dır), belirli bir PID, audit token veya unique ID içindeki bir işlemin Sandbox tarafından **izin verilip verilmediğini** kontrol edebilir.<sup>[[8]](#references)</sup>

[**`sbtool` aracı**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) bir PID'nin belirli işlemleri gerçekleştirip gerçekleştiremeyeceğini kontrol edebilir ([burada derlenmiş halini bulabilirsiniz](https://newosxbook.com/articles/hitsb.html)):
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` içindeki `sandbox_suspend` ve `sandbox_unsuspend` işlevlerini kullanarak sandbox'ı suspend ve unsuspend etmek de mümkündür.

Suspend işlevini çağırmak için, çağıranın bu işlevi çağırmasına yetki vermek amacıyla bazı entitlements kontrol edilir:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Bu sistem çağrısı (#381), ilk argüman olarak çalıştırılacak modülü belirten bir string ve ikinci argüman olarak çalıştırılacak işlevi belirten bir kod bekler. Üçüncü argüman ise çalıştırılan işleve bağlıdır.<sup>[[2]](#references)</sup>

`___sandbox_ms` işlevi, ilk argümanda `"Sandbox"` belirterek `mac_syscall` çağrısını wrap eder; tıpkı `___sandbox_msp` işlevinin `mac_set_proc` (#387) için wrapper olması gibi. Ardından, `___sandbox_ms` tarafından desteklenen bazı kodlar şu tabloda görülebilir:

- **set_profile (#0)**: Bir process'e derlenmiş veya isimlendirilmiş bir profile uygular.
- **platform_policy (#1)**: Platforma özgü policy kontrollerini zorunlu kılar (macOS ve iOS arasında değişir).
- **check_sandbox (#2)**: Belirli bir sandbox operasyonunun manuel kontrolünü gerçekleştirir.
- **note (#3)**: Bir Sandbox'a annotation ekler.
- **container (#4)**: Bir sandbox'a, genellikle debugging veya identification amacıyla annotation ekler.
- **extension_issue (#5)**: Bir process için yeni bir extension oluşturur.
- **extension_consume (#6)**: Verilen bir extension'ı kullanır.
- **extension_release (#7)**: Kullanılan bir extension'a bağlı belleği serbest bırakır.
- **extension_update_file (#8)**: Sandbox içindeki mevcut bir file extension'ın parametrelerini değiştirir.
- **extension_twiddle (#9)**: Mevcut bir file extension'ı ayarlar veya değiştirir (ör. TextEdit, rtf, rtfd).
- **suspend (#10)**: Tüm sandbox kontrollerini geçici olarak suspend eder (uygun entitlements gerektirir).
- **unsuspend (#11)**: Daha önce suspend edilmiş tüm sandbox kontrollerini yeniden başlatır.
- **passthrough_access (#12)**: Sandbox kontrollerini bypass ederek bir kaynağa doğrudan passthrough erişimine izin verir.
- **set_container_path (#13)**: (Yalnızca iOS) Bir app group veya signing ID için container path ayarlar.
- **container_map (#14)**: (Yalnızca iOS) `containermanagerd` üzerinden bir container path alır.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Sandbox içinde user mode metadata ayarlar.
- **inspect (#16)**: Sandbox uygulanmış bir process hakkında debug bilgileri sağlar.
- **dump (#18)**: (macOS 11) Analiz için bir sandbox'ın mevcut profilini dump eder.
- **vtrace (#19)**: Monitoring veya debugging amacıyla sandbox operasyonlarını trace eder.
- **builtin_profile_deactivate (#20)**: (macOS < 11) İsimlendirilmiş profilleri devre dışı bırakır (ör. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Tek bir çağrıda birden fazla `sandbox_check` operasyonu gerçekleştirir.
- **reference_retain_by_audit_token (#28)**: Sandbox kontrollerinde kullanılmak üzere bir audit token için reference oluşturur.
- **reference_release (#29)**: Daha önce retain edilmiş bir audit token reference'ını serbest bırakır.
- **rootless_allows_task_for_pid (#30)**: `task_for_pid` işleminin izinli olup olmadığını doğrular (`csr` kontrollerine benzer).
- **rootless_whitelist_push (#31)**: (macOS) Bir System Integrity Protection (SIP) manifest dosyası uygular.
- **rootless_whitelist_check (preflight) (#32)**: Çalıştırmadan önce SIP manifest dosyasını kontrol eder.
- **rootless_protected_volume (#33)**: (macOS) Bir diske veya partition'a SIP protections uygular.
- **rootless_mkdir_protected (#34)**: Bir directory oluşturma işlemine SIP/DataVault protection uygular.

## Sandbox.kext

iOS'ta kernel extension'ın, değiştirilmelerini önlemek amacıyla tüm profilleri `__TEXT.__const` segmenti içinde **hardcoded** olarak bulundurduğunu belirtmek gerekir. Kernel extension içindeki ilgi çekici işlevlerden bazıları şunlardır:

- **`hook_policy_init`**: `mpo_policy_init` işlevini hook eder ve `mac_policy_register` sonrasında çağrılır. Sandbox'ın başlangıç işlemlerinin çoğunu gerçekleştirir. Ayrıca SIP'yi başlatır.
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` ve ( `PE_i_can_has_debugger` ile boot edilmişse) `security.mac.sandbox.debug_mode` kaydını yaparak sysctl arayüzünü kurar.
- **`hook_policy_syscall`**: İlk argüman olarak `"Sandbox"` ve ikinci argüman olarak operasyonu belirten kod ile `mac_syscall` tarafından çağrılır. İstenen koda göre çalıştırılacak kodu bulmak için bir switch kullanılır.

### MACF Hooks

**`Sandbox.kext`**, MACF aracılığıyla yüzden fazla hook kullanır. Hook'ların çoğu, işlemin gerçekleştirilmesine izin veren bazı basit durumları kontrol eder; aksi durumda **credentials** ve **operation**'a karşılık gelen bir sayı ile çıktı için bir **buffer** kullanarak **`cred_sb_evalutate`** işlevini çağırır.<sup>[[1]](#references)</sup>

Buna iyi bir örnek, `mmap` işlevini hook eden **`_mpo_file_check_mmap`** işlevidir. Bu işlev öncelikle yeni belleğin writable olup olmadığını kontrol eder (writable değilse execution'a izin verir), ardından dyld shared cache için kullanılıp kullanılmadığını kontrol eder ve kullanılıyorsa execution'a izin verir. Son olarak daha ileri allowance kontrolleri gerçekleştirmek için **`sb_evaluate_internal`** (veya wrapper'larından birini) çağırır.

Ayrıca Sandbox'ın kullandığı yüzlerce hook arasından özellikle ilgi çekici 3 hook vardır:

- `mpo_proc_check_for`: Gerekiyorsa ve daha önce uygulanmamışsa profile'ı uygular.
- `mpo_vnode_check_exec`: Bir process ilişkili binary'yi yüklediğinde çağrılır; ardından bir profile kontrolü ve SUID/SGID execution'larını engelleyen bir kontrol gerçekleştirilir.
- `mpo_cred_label_update_execve`: Label atandığında çağrılır. Binary tamamen yüklenmiş ancak henüz execute edilmemiş olduğundan en uzun hook budur. Sandbox object oluşturma, sandbox struct'ını kauth credentials'a attach etme ve mach port'lara erişimi kaldırma gibi işlemleri gerçekleştirir.

**`_cred_sb_evalutate`** işlevinin **`sb_evaluate_internal`** üzerinde bir wrapper olduğunu belirtmek gerekir. Bu işlev, kendisine iletilen credentials'ı alır ve ardından genellikle tüm process'lere varsayılan olarak uygulanan **platform profile**'ı ve daha sonra **specific process profile**'ı değerlendiren **`eval`** işlevini kullanarak değerlendirme gerçekleştirir. Platform profile'ın macOS'taki **SIP** bileşenlerinden biri olduğunu belirtmek gerekir.

## Sandboxd

Sandbox ayrıca `com.apple.sandboxd` XPC Mach service'ini expose eden ve kernel extension'ın iletişim kurmak için kullandığı özel port 14'ü (`HOST_SEATBELT_PORT`) bind eden bir user daemon çalıştırır. MIG kullanarak bazı işlevleri expose eder.

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
