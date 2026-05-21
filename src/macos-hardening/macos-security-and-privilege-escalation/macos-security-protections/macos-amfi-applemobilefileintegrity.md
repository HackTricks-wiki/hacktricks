# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Sistemde çalışan code'un integrity'sini zorlamaya odaklanır ve XNU'nun code signature verification mantığını sağlar. Ayrıca entitlements kontrol edebilir ve debugging'e izin vermek veya task ports elde etmek gibi diğer hassas görevleri de ele alabilir.

Buna ek olarak, bazı işlemler için kext, user space'te çalışan daemon `/usr/libexec/amfid` ile iletişim kurmayı tercih eder. Bu trust relationship, birkaç jailbreak'te abuse edilmiştir.

Son macOS sürümlerinde AMFI artık rahatça bağımsız bir on-disk kext olarak sunulmuyor, bu yüzden reverse etmek genellikle `/System/Library/Extensions` içinde gezinmek yerine **kernelcache** veya bir **KDK** ile çalışmak anlamına gelir.

AMFI, **MACF** policies kullanır ve başlar başlamaz hook'larını kaydeder. Ayrıca, yüklenmesini engellemek veya unload etmek kernel panic tetikleyebilir. Ancak, AMFI'yi zayıflatmaya izin veren bazı boot arguments vardır:

- `amfi_unrestricted_task_for_pid`: Gerekli entitlements olmadan task_for_pid'e izin ver
- `amfi_allow_any_signature`: Herhangi bir code signature'a izin ver
- `cs_enforcement_disable`: code signing enforcement'ı devre dışı bırakmak için sistem genelinde kullanılan argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements içeren platform binaries'leri geçersiz kılar
- `amfi_get_out_of_my_way`: amfi'yi tamamen devre dışı bırakır

Kaydettiği bazı MACF policies şunlardır:

- **`cred_check_label_update_execve:`** Label update yapılır ve 1 döndürülür
- **`cred_label_associate`**: AMFI'nin mac label slot'unu label ile günceller
- **`cred_label_destroy`**: AMFI'nin mac label slot'unu kaldırır
- **`cred_label_init`**: AMFI'nin mac label slot'unda 0'a taşır
- **`cred_label_update_execve`:** Process'in labels'ı değiştirmesine izin verilip verilmemesi gerektiğini görmek için entitlements'ını kontrol eder.
- **`file_check_mmap`:** `mmap`'in memory alıp onu executable olarak ayarlayıp ayarlamadığını kontrol eder. Eğer öyleyse library validation gerekip gerekmediğini kontrol eder ve gerekiyorsa library validation function'ını çağırır.
- **`file_check_library_validation`**: Bir platform binary'nin başka bir platform binary yükleyip yüklemediğini veya process ile yeni yüklenen dosyanın aynı TeamID'ye sahip olup olmadığını kontrol eden library validation function'ını çağırır. Bazı entitlements'lar ayrıca herhangi bir library'nin yüklenmesine izin verir.
- **`policy_initbsd`**: Güvenilen NVRAM Keys'i ayarlar
- **`policy_syscall`**: Binary'nin unrestricted segments'e sahip olup olmadığını, env vars'a izin verilip verilmemesi gerektiğini gibi DYLD policies'yi kontrol eder... bu aynı zamanda bir process `amfi_check_dyld_policy_self()` üzerinden başlatıldığında da çağrılır.
- **`proc_check_inherit_ipc_ports`**: Bir process yeni bir binary çalıştırdığında, process'in task port'u üzerinde SEND rights'a sahip diğer process'lerin bunları koruyup korumaması gerektiğini kontrol eder. Platform binaries'lere izin verilir, `get-task-allow` entitlements'ı bunu sağlar, `task_for_pid-allow` entitlements'ı izinlidir ve aynı TeamID'ye sahip binaries'ler de öyledir.
- **`proc_check_expose_task`**: entitlements'ı zorlar
- **`amfi_exc_action_check_exception_send`**: Bir exception message debugger'a gönderilir
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling sırasında label yaşam döngüsü (debugging)
- **`proc_check_get_task`**: `get-task-allow` gibi, diğer process'lerin task port'u almasına izin veren entitlements'ları ve process'in diğer process'lerin task port'larını almasına izin veren `task_for_pid-allow`'u kontrol eder. Bunlardan hiçbiri yoksa, izin verilip verilmediğini kontrol etmek için `amfid permitunrestricteddebugging`'e gider.
- **`proc_check_mprotect`**: `mprotect`, bölgenin geçerli bir code signature'a sahipmiş gibi ele alınması gerektiğini belirten `VM_PROT_TRUSTED` flag'i ile çağrılırsa reddeder.
- **`vnode_check_exec`**: executable files memory'e yüklendiğinde çağrılır ve sayfalardan herhangi biri geçersiz hale gelirse process'i öldürecek `cs_hard | cs_kill` ayarlar
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` ve `isVnodeQuarantined()` kontrol eder
- **`vnode_check_setextattr`**: get + `com.apple.private.allow-bless` ve internal-installer-equivalent entitlement
- **`vnode_check_signature`**: entitlements, trust cache ve `amfid` kullanarak code signature'ı kontrol etmek için XNU'yu çağıran code
- **`proc_check_run_cs_invalid`**: `ptrace()` çağrılarını (`PT_ATTACH` ve `PT_TRACE_ME`) keser. `get-task-allow`, `run-invalid-allow` ve `run-unsigned-code` entitlements'ından herhangi birini kontrol eder ve hiçbiri yoksa debugging'e izin verilip verilmediğini kontrol eder.
- **`proc_check_map_anon`**: `mmap` **`MAP_JIT`** flag'i ile çağrılırsa, AMFI `dynamic-codesigning` entitlement'ını kontrol eder.

`AMFI.kext`, diğer kernel extensions'lar için de bir API sunar ve bağımlılıklarını şu şekilde bulmak mümkündür:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Bu, `AMFI.kext`'in user mode’da code signature kontrolü yapmak için kullanacağı user mode çalışan daemon’dır.\
`AMFI.kext`’in daemon ile iletişim kurabilmesi için `HOST_AMFID_PORT` özel portu üzerinden mach messages kullanır; bu port özel port `18`’dir.

macOS’ta artık root process’lerin special ports’u hijack etmesi mümkün değildir çünkü bunlar `SIP` tarafından korunur ve yalnızca launchd bunları alabilir. iOS’ta ise response’u geri gönderen process’in CDHash hardcoded olarak `amfid`’nin CDHash’i olup olmadığı kontrol edilir.

`amfid`’den bir binary’yi kontrol etmesinin istendiğini ve bunun response’unu görmek, onu debug edip `mach_msg` içinde bir breakpoint koyarak mümkündür.

Special port üzerinden bir message alındıktan sonra, çağrılan her function’ı ilgili function’a göndermek için **MIG** kullanılır. Ana function’lar kitabın içinde reverse edilmiş ve açıklanmıştır.

### DYLD policy and library validation

Recent `dyld` versions call `amfi_check_dyld_policy_self()` very early from `configureProcessRestrictions()` to ask AMFI whether the process may use `DYLD_*` path variables, interposing, fallback paths, embedded variables, or tolerate failed library insertion. Therefore, when triaging an injection surface it isn't enough to inspect only Mach-O load commands: you also need to inspect the entitlements and runtime flags that AMFI will translate into `dyld` policy.

Practical bir triage loop is:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Modern macOS’ta birçok Apple binary artık doğrudan `com.apple.security.cs.disable-library-validation` taşımıyor; bunun yerine `com.apple.private.security.clear-library-validation` ile geliyor. Bu durumda library validation `execve` zamanında devre dışı bırakılmaz: process, kendi üzerinde `csops(..., CS_OPS_CLEAR_LV, ...)` çağrısı yapmak zorundadır ve XNU bu işlemi yalnızca entitlement mevcutsa çağıran process için izin verir. Offensive açıdan bu önemlidir çünkü bir target, LV’yi açıkça temizleyen code path’e ulaşana kadar injectable olmayabilir (örneğin, optional plugins yüklemeden hemen önce).

## Provisioning Profiles

Bir provisioning profile, code sign etmek için kullanılabilir. Code sign etmek ve test etmek için kullanılabilen **Developer** profilleri vardır ve tüm device’larda kullanılabilen **Enterprise** profilleri vardır.

Bir App Apple Store’a gönderildikten sonra, eğer onaylanırsa, Apple tarafından imzalanır ve provisioning profile artık gerekli olmaz.

Bir profile genellikle `.mobileprovision` veya `.provisionprofile` extension’ını kullanır ve şu şekilde dump edilebilir:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bazen sertifikalı olarak da anılsa da, bu provisioning profile’lar bir sertifikadan daha fazlasını içerir:

- **AppIDName:** Uygulama Kimliği
- **AppleInternalProfile**: Bunu bir Apple Internal profile olarak belirtir
- **ApplicationIdentifierPrefix**: AppIDName’in başına eklenir (TeamIdentifier ile aynı)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında tarih
- **DeveloperCertificates**: Base64 veri olarak kodlanmış (genellikle bir) sertifika dizisi
- **Entitlements**: Bu profile için izin verilen entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında son kullanma tarihi
- **Name**: Uygulama Adı, AppIDName ile aynıdır
- **ProvisionedDevices**: Bu profile için geçerli olan UDID’lerin bir dizisi (developer certificates için)
- **ProvisionsAllDevices**: Bir boolean (enterprise certificates için true)
- **TeamIdentifier**: Uygulama arası etkileşim amaçları için geliştiriciyi tanımlamakta kullanılan (genellikle bir) alfanümerik string dizisi
- **TeamName**: Geliştiriciyi tanımlamak için kullanılan insan tarafından okunabilir ad
- **TimeToLive**: Sertifikanın geçerliliği (gün cinsinden)
- **UUID**: Bu profile için Evrensel Benzersiz Tanımlayıcı
- **Version**: Şu anda 1 olarak ayarlı

Entitlements girdisinin kısıtlı bir entitlements kümesi içereceğini ve provisioning profile’ın yalnızca bu belirli entitlements’ları verebileceğini, böylece Apple private entitlements verilmesinin önleneceğini unutmayın.

Profile’lar genellikle `/var/MobileDeviceProvisioningProfiles` altında bulunur ve bunlar **`security cms -D -i /path/to/profile`** ile kontrol edilebilir.

## **libmis.dylib**

Bu, `amfid`’nin bir şeylere izin verip vermemesi gerektiğini sormak için çağırdığı dış kütüphanedir. Tarihsel olarak, her şeye izin verecek backdoored bir sürümünü çalıştırarak jailbreaking içinde istismar edilmiştir.

macOS’ta bu, `MobileDevice.framework` içindedir.

## AMFI Trust Caches

Trust caches yalnızca bir iOS kavramı değildir. Modern macOS’ta, özellikle **Apple silicon** üzerinde, static trust cache ve loadable trust caches Secure Boot zincirinin bir parçasıdır. Bir Mach-O’nun **CodeDirectory hash** değeri orada mevcut olduğunda, AMFI başlangıç anında ek authenticity checks yapmadan ona **platform privilege** verebilir. Bu aynı zamanda Apple’ın platform binary’leri belirli bir OS sürümüne kilitleyebilmesini ve daha eski Apple-signed binary’lerin daha yeni sistemlerde yeniden oynatılmasını engelleyebilmesini sağlar.

Son macOS sürümlerinde trust-cache metadata ayrıca **launch constraints** ile de bağlantılıdır; bu nedenle yanlış parent/location’dan başlatılan kopyalanmış system app’ler ve binary’ler, hâlâ Apple-signed olsalar bile AMFI tarafından reddedilebilir. Ayrıntılı extraction ve reversing iş akışı burada ele alınmıştır:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS ve jailbreak araştırmalarında, ad-hoc signed binary’leri whitelist etmek için hâlâ geleneksel **loadable trust caches** modeliyle karşılaşabilirsiniz.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
