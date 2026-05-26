# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Sistemde çalışan code’un integrity’sini zorlamaya odaklanır ve XNU’nun code signature verification mantığını sağlar. Ayrıca entitlements kontrol edebilir ve debugging’e izin verme veya task ports elde etme gibi diğer hassas görevleri de yönetebilir.

Buna ek olarak, bazı işlemler için kext, user space’te çalışan daemon `/usr/libexec/amfid` ile iletişim kurmayı tercih eder. Bu trust relationship, birkaç jailbreak içinde abused edilmiştir.

Yeni macOS sürümlerinde AMFI artık bağımsız bir on-disk kext olarak kolayca görünmez; bu yüzden reverse etmek genellikle `/System/Library/Extensions` içinde gezinmek yerine **kernelcache** veya bir **KDK** ile çalışmayı gerektirir.

AMFI, **MACF** policies kullanır ve başlatıldığı anda hook’larını kaydeder. Ayrıca, yüklenmesini engellemek veya unload etmek kernel panic tetikleyebilir. Ancak AMFI’yi zayıflatmaya izin veren bazı boot arguments vardır:

- `amfi_unrestricted_task_for_pid`: Gerekli entitlements olmadan task_for_pid’e izin ver
- `amfi_allow_any_signature`: Herhangi bir code signature’a izin ver
- `cs_enforcement_disable`: code signing enforcement’ı sistem genelinde devre dışı bırakmak için kullanılan argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements içeren platform binaries’leri void et
- `amfi_get_out_of_my_way`: amfi’yi tamamen devre dışı bırakır

Bunlar kaydettiği bazı MACF policies’tir:

- **`cred_check_label_update_execve:`** Label update yapılır ve 1 döner
- **`cred_label_associate`**: AMFI’nin mac label slot’unu label ile günceller
- **`cred_label_destroy`**: AMFI’nin mac label slot’unu kaldırır
- **`cred_label_init`**: AMFI’nin mac label slot’unda 0’a geçer
- **`cred_label_update_execve`:** Label’ları değiştirmesine izin verilip verilmemesi gerektiğini görmek için process’in entitlements’ını kontrol eder.
- **`file_check_mmap`:** mmap’in memory alıp bunu executable olarak ayarlayıp ayarlamadığını kontrol eder. Böyle bir durumda library validation gerekip gerekmediğini kontrol eder ve gerekiyorsa library validation function’ını çağırır.
- **`file_check_library_validation`**: Diğer şeylerin yanında bir platform binary’nin başka bir platform binary yükleyip yüklemediğini veya process ile yeni yüklenen file’ın aynı TeamID’ye sahip olup olmadığını kontrol eden library validation function’ını çağırır. Bazı entitlements ayrıca herhangi bir library yüklemeye izin verir.
- **`policy_initbsd`**: Güvenilir NVRAM Keys ayarlar
- **`policy_syscall`**: Binary’nin unrestricted segments’e sahip olup olmadığı, env vars’a izin verilip verilmeyeceği gibi DYLD policies’i kontrol eder... bu ayrıca bir process `amfi_check_dyld_policy_self()` üzerinden başlatıldığında da çağrılır.
- **`proc_check_inherit_ipc_ports`**: Bir process yeni bir binary çalıştırdığında, process’in task port’u üzerinde SEND rights’a sahip diğer process’lerin bunları koruyup korumaması gerektiğini kontrol eder. Platform binaries’e izin verilir, `get-task-allow` entitlements buna izin verir, `task_for_pid-allow` entitles’ları izinlidir ve aynı TeamID’ye sahip binaries için de izin verilir.
- **`proc_check_expose_task`**: entitlements’ı zorlar
- **`amfi_exc_action_check_exception_send`**: Bir exception message debugger’a gönderilir
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling (debugging) sırasında label lifecycle
- **`proc_check_get_task`**: `get-task-allow` gibi, diğer process’lerin task port’u almasına izin veren entitlements ile `task_for_pid-allow` gibi, process’in diğer process’lerin task port’larını almasına izin veren entitlements’ı kontrol eder. Bunların hiçbiri yoksa, bunun izinli olup olmadığını kontrol etmek için `amfid permitunrestricteddebugging`’e başvurur.
- **`proc_check_mprotect`**: `mprotect`, bölgenin valid bir code signature’a sahipmiş gibi ele alınması gerektiğini belirten `VM_PROT_TRUSTED` flag’i ile çağrılırsa reddeder
- **`vnode_check_exec`**: Executable files memory’ye yüklendiğinde çağrılır ve sayfalardan herhangi biri geçersiz hale gelirse process’i öldürecek `cs_hard | cs_kill` ayarlar
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` ve `isVnodeQuarantined()` kontrol eder
- **`vnode_check_setextattr`**: get + `com.apple.private.allow-bless` ve internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Entitlements, trust cache ve `amfid` kullanarak code signature’ı kontrol etmek için XNU’ya çağrı yapan code
- **`proc_check_run_cs_invalid`**: `ptrace()` çağrılarını (`PT_ATTACH` ve `PT_TRACE_ME`) intercept eder. `get-task-allow`, `run-invalid-allow` ve `run-unsigned-code` entitlements’ından herhangi birini kontrol eder ve hiçbiri yoksa debugging’e izin verilip verilmediğini kontrol eder.
- **`proc_check_map_anon`**: Eğer `mmap`, **`MAP_JIT`** flag’i ile çağrılırsa, AMFI `dynamic-codesigning` entitlement’ını kontrol eder.

`AMFI.kext` ayrıca diğer kernel extensions için de bir API expose eder ve bağımlılıklarını şu şekilde bulmak mümkündür:
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

Bu, `AMFI.kext`’in user mode’da code signature’ları kontrol etmek için kullanacağı user mode çalışan daemon’dır.\
`AMFI.kext`’in daemon ile iletişim kurması için `HOST_AMFID_PORT` üzerinden mach mesajları kullanır; bu özel port `18`’dir.

macOS’ta artık root process’lerin özel portları hijack etmesi mümkün değildir çünkü bunlar `SIP` tarafından korunur ve yalnızca launchd bunları alabilir. iOS’ta ise response’u geri gönderen process’in CDHash hardcoded olarak `amfid`’in CDHash’ı olacak şekilde kontrol edilir.

`amfid`’nin bir binary’yi kontrol etmesinin istendiğini ve response’unu görmek, onu debug edip `mach_msg` içinde bir breakpoint koyarak mümkündür.

Özel port üzerinden bir mesaj alındığında, çağırdığı her function’ı ilgili function’a göndermek için **MIG** kullanılır. Ana function’lar tersine mühendislik yapılarak kitap içinde açıklanmıştır.

### DYLD policy and library validation

Yeni `dyld` sürümleri, process `DYLD_*` path variables, interposing, fallback paths, embedded variables kullanabilir mi ya da failed library insertion’ı tolere edebilir mi diye AMFI’ye sormak için `configureProcessRestrictions()` içinden çok erken bir aşamada `amfi_check_dyld_policy_self()` çağırır. Bu nedenle, bir injection surface’i incelerken yalnızca Mach-O load commands’a bakmak yeterli değildir: ayrıca AMFI’nin `dyld` policy’ye çevireceği entitlements ve runtime flags de incelenmelidir.

Pratik bir triage döngüsü şöyledir:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Modern macOS’ta birçok Apple binary artık doğrudan `com.apple.security.cs.disable-library-validation` taşımıyor ve bunun yerine `com.apple.private.security.clear-library-validation` ile geliyor. Bu durumda library validation `execve` sırasında devre dışı bırakılmaz: süreç kendisi üzerinde `csops(..., CS_OPS_CLEAR_LV, ...)` çağırmak zorundadır ve XNU bu işlemi yalnızca entitlement mevcut olduğunda çağıran süreç için izin verir. Saldırı açısından bu önemlidir çünkü bir hedef, LV’yi açıkça temizleyen code path’e ulaştıktan **sonra** injectable hale gelebilir (örneğin, optional plugins yüklenmeden hemen önce).

## Provisioning Profiles

Bir provisioning profile code imzalamak için kullanılabilir. Code imzalamak ve test etmek için kullanılabilen **Developer** profilleri ve tüm cihazlarda kullanılabilen **Enterprise** profilleri vardır.

Bir App Apple Store’a gönderildikten sonra, eğer onaylanırsa Apple tarafından imzalanır ve provisioning profile artık gerekli olmaz.

Bir profile genellikle `.mobileprovision` veya `.provisionprofile` uzantısı kullanır ve şununla dump edilebilir:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bazen certificated olarak anılsa da, bu provisioning profile'lar bir certificate'tan daha fazlasını içerir:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Bunu bir Apple Internal profile olarak tanımlar
- **ApplicationIdentifierPrefix**: AppIDName önüne eklenir (TeamIdentifier ile aynı)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında tarih
- **DeveloperCertificates**: Base64 verisi olarak kodlanmış (genellikle bir) certificate dizisi
- **Entitlements**: Bu profile için izin verilen entitlements ile birlikte entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında son kullanma tarihi
- **Name**: Application Name, AppIDName ile aynı
- **ProvisionedDevices**: Bu profile geçerli olan UDID'lerin (developer certificates için) dizisi
- **ProvisionsAllDevices**: Bir boolean (enterprise certificates için true)
- **TeamIdentifier**: Uygulamalar arası etkileşim amacıyla developer'ı tanımlamak için kullanılan (genellikle bir) alfanümerik string dizisi
- **TeamName**: Developer'ı tanımlamak için kullanılan, insan tarafından okunabilir bir isim
- **TimeToLive**: certificate'ın geçerliliği (gün cinsinden)
- **UUID**: Bu profile ait Evrensel Benzersiz Tanımlayıcı
- **Version**: Şu anda 1 olarak ayarlı

Entitlements girdisinin kısıtlı bir entitlements kümesi içereceğini ve provisioning profile'ın yalnızca bu belirli entitlements'ları verebileceğini unutmayın; böylece Apple private entitlements verilmesi engellenir.

Profile'ların genellikle `/var/MobileDeviceProvisioningProfiles` içinde bulunduğunu ve bunların **`security cms -D -i /path/to/profile`** ile kontrol edilebileceğini unutmayın

## **libmis.dylib**

Bu, `amfid`'nin bir şeyi izin verip vermemesi gerektiğini sormak için çağırdığı harici library'dir. Tarihsel olarak jailbreaking içinde, her şeye izin verecek backdoored bir sürümü çalıştırılarak kötüye kullanılmıştır.

macOS'ta bu, `MobileDevice.framework` içindedir.

## AMFI Trust Caches

Trust cache'ler yalnızca bir iOS konsepti değildir. Modern macOS'ta, özellikle **Apple silicon** üzerinde, static trust cache ve loadable trust cache'ler Secure Boot zincirinin bir parçasıdır. Bir Mach-O'nun **CodeDirectory hash**'i burada mevcut olduğunda, AMFI başlangıçta ek authenticity checks yapmadan ona **platform privilege** verebilir. Bu aynı zamanda Apple'ın platform binary'lerini belirli bir OS sürümüne kilitlemesine ve daha eski Apple-imzalı binary'lerin daha yeni sistemlerde yeniden oynatılmasını engellemesine de olanak tanır.

Son macOS sürümlerinde trust-cache metadata'sı ayrıca **launch constraints** ile bağlantılıdır; bu yüzden kopyalanmış system app'ler ve yanlış parent/location'dan başlatılan binary'ler, hâlâ Apple-signed olsalar bile AMFI tarafından reddedilebilir. Ayrıntılı extraction ve reversing workflow şu bölümde anlatılmaktadır:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS ve jailbreak research içinde, ad-hoc signed binary'leri whitelist etmek için kullanılan geleneksel **loadable trust caches** modelini hâlâ bulabilirsiniz.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
