# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MacOS Sandbox (başlangıçta Seatbelt olarak adlandırılıyordu), sandbox içinde çalışan **uygulamaları**, uygulamanın çalıştığı Sandbox profilinde belirtilen **izin verilen eylemlerle** sınırlar. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

**`com.apple.security.app-sandbox`** **entitlement** değerine sahip tüm uygulamalar sandbox içinde çalıştırılır. **Apple binary dosyaları** genellikle bir Sandbox içinde çalıştırılır ve **App Store'daki tüm uygulamalar bu entitlement değerine sahiptir**. Bu nedenle birçok uygulama sandbox içinde çalıştırılır.<sup>[[4]](#references)</sup>

Bir process'in ne yapıp yapamayacağını denetlemek için **Sandbox**, **MACF** kullanarak bir process'in gerçekleştirmeyi deneyebileceği neredeyse tüm işlemlerde (çoğu syscall dahil) **hook'lara** sahiptir. Ancak uygulamanın **entitlement** değerlerine **bağlı olarak** Sandbox, process'e karşı daha izin verici olabilir.

Sandbox'ın bazı önemli bileşenleri şunlardır:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userland içinde çalışan bir **daemon** `/usr/libexec/sandboxd`
- **container**'lar `~/Library/Containers`

### Container'lar

Sandbox ile korunan her uygulama, `~/Library/Containers/{CFBundleIdentifier}` içinde kendi container'ına sahip olur:
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
Her bundle id klasörünün içinde, Home klasörünü taklit eden bir yapıyla App'in **plist** dosyasını ve **Data directory**'sini bulabilirsiniz:
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
> Symlink'ler Sandbox'tan "kaçıp" diğer klasörlere erişmek için mevcut olsa bile App'in bunlara erişmek için **izinlere** sahip olması gerekir. Bu izinler, **`.plist`** içindeki `RedirectablePaths` bölümünde bulunur.

**`SandboxProfileData`**, derlenmiş sandbox profilinin B64'e escape edilmiş CFData'sıdır.
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
> Bir Sandbox uygulaması tarafından oluşturulan/değiştirilen her şey **quarantine attribut**e sahip olur. Bu, Sandbox uygulaması **`open`** kullanarak bir şeyi çalıştırmaya çalıştığında Gatekeeper'ı tetikleyerek bir sandbox alanını engeller.

## Sandbox Profilleri

Sandbox profilleri, ilgili **Sandbox** içinde nelerin **izinli/yasak** olduğunu belirten yapılandırma dosyalarıdır. [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programlama dilini kullanan **Sandbox Profile Language (SBPL)** dilini kullanır.

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
> Hangi eylemlere izin verilebileceğini veya verilemeyeceğini görmek için bu [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) çalışmasına göz atın.<sup>[[5]](#references)</sup>
>
> Bir profile ait derlenmiş sürümde işlemlerin adlarının, dylib ve kext tarafından bilinen bir dizideki girdilerle değiştirildiğini; bunun da derlenmiş sürümü daha kısa ve okunması daha zor hâle getirdiğini unutmayın.

`mdnsresponder` hizmeti gibi önemli **system services** de kendi özel **sandbox**'ları içinde çalışır. Bu özel **sandbox profiles** dosyalarını şu konumlarda görüntüleyebilirsiniz:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Diğer sandbox profiles şu adreste incelenebilir: [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- iOS'ta platform profile, binary içindeki `_platform_profile_data` içerisinde bulunan sandbox `.kext` dosyasındadır.

**App Store** uygulamaları **`/System/Library/Sandbox/Profiles/application.sb`** **profile**'ını kullanır. Bu profile içinde **`com.apple.security.network.server`** gibi entitlements'ların bir process'in ağı kullanmasına nasıl izin verdiğini görebilirsiniz.

Daha sonra bazı **Apple daemon services**, `/System/Library/Sandbox/Profiles/*.sb` veya `/usr/share/sandbox/*.sb` konumlarında bulunan farklı profile'ları kullanır. Bu sandbox'lar, `sandbox_init_XXX` API'sini çağıran ana function içinde uygulanır.<sup>[[3]](#references)</sup>

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
> Windows üzerinde çalışan **Apple-authored** **software**'in, uygulama sandboxing gibi **additional security precautions** içermediğini unutmayın.

Bypasses örnekleri:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (adı `~$` ile başlayan dosyaları sandbox dışına yazabiliyorlar).<sup>[[7]](#references)</sup>

### Sandbox Tracing

#### Profil üzerinden

Sandbox'ın bir action kontrol edildiğinde gerçekleştirdiği tüm check'leri trace etmek mümkündür. Bunun için aşağıdaki profile'ı oluşturun:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Ve ardından bu profili kullanarak bir şey çalıştırın:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out` içinde, gerçekleştirilen her sandbox check'ini çağrıldığı her seferde görebilirsiniz (bu nedenle çok sayıda duplicate bulunur).

Sandbox'ı **`-t`** parametresini kullanarak trace etmek de mümkündür: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API aracılığıyla

`libsystem_sandbox.dylib` tarafından export edilen `sandbox_set_trace_path` işlevi, sandbox kontrollerinin yazılacağı bir trace dosya adı belirtmenize olanak tanır.\
Benzer bir işlem `sandbox_vtrace_enable()` çağrılarak ve ardından buffer'daki log hataları `sandbox_vtrace_report()` çağrısıyla alınarak da gerçekleştirilebilir.

### Sandbox İncelemesi

`libsandbox.dylib`, bir process'in sandbox durumunun (extensions dahil) listesini sağlayan `sandbox_inspect_pid` adlı bir işlev export eder. Ancak bu işlevi yalnızca platform binary'leri kullanabilir.

### MacOS & iOS Sandbox Profilleri

MacOS, sistem sandbox profillerini iki konumda depolar: **/usr/share/sandbox/** ve **/System/Library/Sandbox/Profiles**.

Ayrıca bir third-party uygulama _**com.apple.security.app-sandbox**_ entitlement'ına sahipse sistem, **/System/Library/Sandbox/Profiles/application.sb** profilini bu process'e uygular.

iOS'ta varsayılan profilin adı **container**'dır ve SBPL metin gösterimine sahip değiliz. Memory'de bu sandbox, sandbox'taki her permission için Allow/Deny binary tree olarak temsil edilir.

### App Store uygulamalarında Custom SBPL

Şirketlerin uygulamalarını varsayılan profil yerine **custom Sandbox profilleriyle** çalıştırması mümkün olabilir. Bunun için Apple tarafından authorize edilmesi gereken **`com.apple.security.temporary-exception.sbpl`** entitlement'ını kullanmaları gerekir.

Bu entitlement'ın tanımını **`/System/Library/Sandbox/Profiles/application.sb:`** içinde kontrol etmek mümkündür.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Bu, **bu entitlement sonrasındaki string'i** bir Sandbox profili olarak **eval** edecektir.

### Sandbox Profilini Derleme ve Tersine Derleme

**`sandbox-exec`** aracı, `libsandbox.dylib` içindeki `sandbox_compile_*` fonksiyonlarını kullanır. Dışa aktarılan ana fonksiyonlar şunlardır: `sandbox_compile_file` (bir dosya yolu ve `-f` parametresini bekler), `sandbox_compile_string` (bir string ve `-p` parametresini bekler), `sandbox_compile_name` (bir container adı ve `-n` parametresini bekler), `sandbox_compile_entitlements` (entitlements plist'i bekler).

Bu tersine mühendislik uygulanmış ve [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c), **`sandbox-exec`** aracının derlenmiş Sandbox profilini bir dosyaya yazmasını sağlar.

Ayrıca bir process'i bir container içinde kısıtlamak için `sandbox_spawnattrs_set[container/profilename]` çağrılabilir ve bir container ya da önceden var olan bir profil geçirilebilir.

## Debug ve Sandbox Bypass

macOS'ta, process'lerin kernel tarafından başlangıçtan itibaren Sandbox'a alındığı iOS'un aksine, **process'lerin Sandbox'a kendilerinin opt-in olması gerekir**. Bu, macOS'ta bir process aktif olarak Sandbox'a girmeye karar verene kadar Sandbox tarafından kısıtlanmadığı anlamına gelir; ancak App Store uygulamaları her zaman Sandbox'a alınır.

Process'ler `com.apple.security.app-sandbox` entitlement'ına sahipse userland'den başlatıldıklarında otomatik olarak Sandbox'a alınır. Bu sürecin ayrıntılı açıklaması için şuraya bakın:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions, bir nesneye ek ayrıcalıklar verilmesini sağlar ve aşağıdaki fonksiyonlardan birinin çağrılmasıyla verilir:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions, process credentials içinden erişilebilen ikinci MACF label slot'unda saklanır. Aşağıdaki **`sbtool`** bu bilgilere erişebilir.

Extensions'ın genellikle izin verilen process'ler tarafından verildiğini unutmayın; örneğin `tccd`, bir process fotoğraflara erişmeyi denediğinde ve bir XPC mesajı üzerinden izin verildiğinde `com.apple.tcc.kTCCServicePhotos` extension token'ını verir. Ardından process, extension token'ını tüketerek kendisine eklenmesini sağlamalıdır.\
Extension token'larının, verilen izinleri encode eden uzun hexadecimal değerler olduğunu unutmayın. Ancak izin verilen PID'yi sabit olarak içermedikleri için token'a erişimi olan herhangi bir process **birden fazla process tarafından tüketilebilir**.

Extensions'ın entitlements ile de yakından ilişkili olduğunu unutmayın; bu nedenle belirli entitlements'a sahip olmak belirli extensions'ları otomatik olarak verebilir.

### **PID Ayrıcalıklarını Kontrol Etme**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** fonksiyonları (bir `__mac_syscall`'dır), belirli bir PID, audit token veya unique ID için bir işlemin Sandbox tarafından **izin verilip verilmediğini** kontrol edebilir.<sup>[[8]](#references)</sup>

[**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c), bir PID'nin belirli işlemleri gerçekleştirip gerçekleştiremeyeceğini kontrol edebilir ([compiled here](https://newosxbook.com/articles/hitsb.html) adresinde derlenmiş halini bulabilirsiniz):
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib` içindeki `sandbox_suspend` ve `sandbox_unsuspend` fonksiyonlarını kullanarak sandbox'ı suspend ve unsuspend etmek de mümkündür.

Suspend fonksiyonunu çağırmak için, çağıranın bunu çağırmaya yetkili olup olmadığını doğrulamak amacıyla bazı entitlements kontrol edilir:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Bu system call (#381), çalıştırılacak modülü belirten bir string ilk argüman ve çalıştırılacak fonksiyonu belirten bir code ikinci argüman bekler. Üçüncü argüman ise çalıştırılan fonksiyona bağlıdır.<sup>[[2]](#references)</sup>

`___sandbox_ms` fonksiyonu, ilk argümanda `"Sandbox"` belirterek `mac_syscall` çağrısını wrap eder; tıpkı `___sandbox_msp` fonksiyonunun `mac_set_proc` (#387) için wrapper olması gibi. Ardından, `___sandbox_ms` tarafından desteklenen code'lardan bazıları bu tabloda bulunabilir:

- **set_profile (#0)**: Bir process'e derlenmiş veya adlandırılmış bir profile uygular.
- **platform_policy (#1)**: Platforma özgü policy kontrollerini zorunlu kılar (macOS ve iOS arasında farklılık gösterir).
- **check_sandbox (#2)**: Belirli bir sandbox operation için manuel kontrol gerçekleştirir.
- **note (#3)**: Bir Sandbox'a annotation ekler.
- **container (#4)**: Bir sandbox'a, genellikle debugging veya identification amacıyla, annotation ekler.
- **extension_issue (#5)**: Bir process için yeni bir extension oluşturur.
- **extension_consume (#6)**: Belirtilen bir extension'ı consume eder.
- **extension_release (#7)**: Consume edilmiş bir extension'a bağlı memory'yi serbest bırakır.
- **extension_update_file (#8)**: Sandbox içindeki mevcut bir file extension'ın parametrelerini değiştirir.
- **extension_twiddle (#9)**: Mevcut bir file extension'ı (ör. TextEdit, rtf, rtfd) ayarlar veya değiştirir.
- **suspend (#10)**: Tüm sandbox kontrollerini geçici olarak suspend eder (uygun entitlements gerektirir).
- **unsuspend (#11)**: Daha önce suspend edilmiş tüm sandbox kontrollerini resume eder.
- **passthrough_access (#12)**: Sandbox kontrollerini bypass ederek bir resource'a doğrudan passthrough access sağlar.
- **set_container_path (#13)**: (Yalnızca iOS) Bir app group veya signing ID için container path ayarlar.
- **container_map (#14)**: (Yalnızca iOS) `containermanagerd` üzerinden bir container path alır.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Sandbox içinde user mode metadata ayarlar.
- **inspect (#16)**: Sandboxed bir process hakkında debug bilgisi sağlar.
- **dump (#18)**: (macOS 11) Analiz için bir sandbox'ın mevcut profile'ını dump eder.
- **vtrace (#19)**: Monitoring veya debugging amacıyla sandbox operation'larını trace eder.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Adlandırılmış profile'ları (ör. `pe_i_can_has_debugger`) deactivate eder.
- **check_bulk (#21)**: Tek bir çağrıda birden fazla `sandbox_check` operation'ı gerçekleştirir.
- **reference_retain_by_audit_token (#28)**: Sandbox kontrollerinde kullanılmak üzere bir audit token için reference oluşturur.
- **reference_release (#29)**: Daha önce retain edilmiş bir audit token reference'ını release eder.
- **rootless_allows_task_for_pid (#30)**: `task_for_pid` kullanımına izin verilip verilmediğini doğrular (`csr` kontrollerine benzer).
- **rootless_whitelist_push (#31)**: (macOS) Bir System Integrity Protection (SIP) manifest file'ı uygular.
- **rootless_whitelist_check (preflight) (#32)**: SIP manifest file'ını execution öncesinde kontrol eder.
- **rootless_protected_volume (#33)**: (macOS) Bir disk veya partition'a SIP protections uygular.
- **rootless_mkdir_protected (#34)**: Bir directory creation process'ine SIP/DataVault protection uygular.

## Sandbox.kext

iOS'ta kernel extension'ın, değiştirilmelerini önlemek amacıyla tüm profile'ları `__TEXT.__const` segment'i içinde **hardcoded** olarak barındırdığını unutmayın. Kernel extension içindeki bazı ilginç fonksiyonlar şunlardır:

- **`hook_policy_init`**: `mpo_policy_init` fonksiyonunu hook eder ve `mac_policy_register` sonrasında çağrılır. Sandbox'ın initializations işlemlerinin çoğunu gerçekleştirir. Ayrıca SIP'yi initialize eder.
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` ve ( `PE_i_can_has_debugger` ile boot edilmişse) `security.mac.sandbox.debug_mode` sysctl interface'ini register ederek hazırlar.
- **`hook_policy_syscall`**: İlk argüman olarak `"Sandbox"` ve ikinci argümanda operation'ı belirten code ile `mac_syscall` tarafından çağrılır. İstenen code'a göre çalıştırılacak code'u bulmak için bir switch kullanılır.

### MACF Hooks

**`Sandbox.kext`**, MACF aracılığıyla yüzden fazla hook kullanır. Hook'ların çoğu, action'ın gerçekleştirilmesine izin veren bazı trivial case'leri kontrol eder; izin verilemiyorsa MACF'den alınan **credentials**, gerçekleştirilecek **operation**'a karşılık gelen bir number ve output için bir **buffer** ile **`cred_sb_evalutate`** fonksiyonunu çağırır.<sup>[[1]](#references)</sup>

Buna iyi bir örnek, `mmap`'i hook eden **`_mpo_file_check_mmap`** fonksiyonudur. Bu fonksiyon öncelikle yeni memory'nin writable olup olmadığını kontrol eder (writable değilse execution'a izin verir), ardından dyld shared cache için kullanılıp kullanılmadığını kontrol eder ve kullanılıyorsa execution'a izin verir; son olarak daha ileri allowance kontrolleri gerçekleştirmek için **`sb_evaluate_internal`** (veya wrapper'larından birini) çağırır.

Ayrıca Sandbox'ın kullandığı yüzlerce hook arasından özellikle ilginç olan 3 hook vardır:

- `mpo_proc_check_for`: Gerekiyorsa ve daha önce uygulanmamışsa profile'ı uygular.
- `mpo_vnode_check_exec`: Bir process ilişkili binary'yi yüklediğinde çağrılır; ardından bir profile check gerçekleştirilir ve SUID/SGID execution'larını yasaklayan bir check yapılır.
- `mpo_cred_label_update_execve`: Label atandığında çağrılır. Bu en uzun olanıdır; binary tamamen load edilmiş ancak henüz execute edilmemişken çağrılır. Sandbox object'i oluşturmak, sandbox struct'ını kauth credentials'a attach etmek ve mach port'lara erişimi kaldırmak gibi işlemler gerçekleştirir.

**`_cred_sb_evalutate`** fonksiyonunun **`sb_evaluate_internal`** üzerinde bir wrapper olduğunu unutmayın. Bu fonksiyon, kendisine geçirilen credentials'ı alır ve ardından genellikle varsayılan olarak tüm process'lere uygulanan **platform profile**'ı ve daha sonra **specific process profile**'ı değerlendiren **`eval`** fonksiyonunu kullanarak evaluation gerçekleştirir. Platform profile'ın macOS'taki **SIP**'nin ana bileşenlerinden biri olduğunu unutmayın.

## Sandboxd

Sandbox'ın ayrıca `com.apple.sandboxd` XPC Mach service'ini expose eden ve kernel extension'ın iletişim kurmak için kullandığı özel port 14'ü (`HOST_SEATBELT_PORT`) bind eden bir user daemon'ı vardır. MIG kullanarak bazı fonksiyonları expose eder.

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
