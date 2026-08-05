# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext ve amfid

Sistemde çalışan kodun bütünlüğünü zorlamaya odaklanır ve XNU'nun kod imzası doğrulamasının arkasındaki mantığı sağlar. Ayrıca entitlement'ları kontrol edebilir ve debugging'e izin verme veya task port'larını alma gibi diğer hassas görevleri gerçekleştirebilir.

Bununla birlikte, bazı işlemler için kext, user space'te çalışan daemon `/usr/libexec/amfid` ile iletişim kurmayı tercih eder. Bu güven ilişkisi çeşitli jailbreak'lerde kötüye kullanılmıştır.

Güncel macOS sürümlerinde AMFI artık disk üzerinde bağımsız bir kext olarak uygun şekilde sunulmamaktadır; bu nedenle reversing işlemi genellikle `/System/Library/Extensions` dizinine göz atmak yerine **kernelcache** veya **KDK** üzerinden çalışmayı gerektirir.

AMFI, **MACF** politikalarını kullanır ve başlatıldığı anda hook'larını kaydeder. Ayrıca yüklenmesini engellemek veya yüklemesini kaldırmak kernel panic'i tetikleyebilir. Bununla birlikte, AMFI'yi devre dışı bırakmaya izin veren bazı boot argümanları vardır:

- `amfi_unrestricted_task_for_pid`: Gerekli entitlement'lar olmadan task_for_pid kullanılmasına izin verir
- `amfi_allow_any_signature`: Herhangi bir code signature'a izin verir
- `cs_enforcement_disable`: Code signing enforcement'ı sistem genelinde devre dışı bırakmak için kullanılan argüman
- `amfi_prevent_old_entitled_platform_binaries`: Entitlement'lara sahip platform binary'lerini geçersiz kılar
- `amfi_get_out_of_my_way`: amfi'yi tamamen devre dışı bırakır

Bunlar, kaydettiği MACF politikalarından bazılarıdır:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`**: Label güncellemesi gerçekleştirilir ve 1 döndürülür
- **`cred_label_associate`**: AMFI'nin mac label slot'unu label ile günceller
- **`cred_label_destroy`**: AMFI'nin mac label slot'unu kaldırır
- **`cred_label_init`**: AMFI'nin mac label slot'una 0 taşır
- **`cred_label_update_execve:`**: Label'ları değiştirmesine izin verilip verilmediğini görmek için process'in entitlement'larını kontrol eder.
- **`file_check_mmap:`**: mmap'in memory alıp bunu executable olarak ayarlayıp ayarlamadığını kontrol eder. Bu durumda library validation gerekip gerekmediğini kontrol eder ve gerekiyorsa library validation function'ı çağırır.
- **`file_check_library_validation`**: Diğer şeylerin yanı sıra bir platform binary'sinin başka bir platform binary'si yükleyip yüklemediğini veya process ile yeni yüklenen file'ın aynı TeamID'ye sahip olup olmadığını kontrol eden library validation function'ı çağırır. Belirli entitlement'lar herhangi bir library'nin yüklenmesine de izin verir.
- **`policy_initbsd`**: Güvenilen NVRAM Keys'i ayarlar
- **`policy_syscall`**: Binary'nin unrestricted segment'lara sahip olup olmadığı, env vars'a izin verilip verilmeyeceği gibi DYLD politikalarını kontrol eder... Bu ayrıca bir process `amfi_check_dyld_policy_self()` aracılığıyla başlatıldığında da çağrılır.
- **`proc_check_inherit_ipc_ports`**: Bir process yeni bir binary çalıştırdığında, diğer process'lerin process'in task port'u üzerinde SEND haklarına sahip olması durumunda bu hakları koruyup korumaması gerektiğini kontrol eder. Platform binary'lerine izin verilir, `get-task-allow` entitlement'ı buna izin verir, `task_for_pid-allow` entitlement'larına izin verilir ve aynı TeamID'ye sahip binary'lere izin verilir.
- **`proc_check_expose_task`**: Entitlement'ları zorunlu kılar
- **`amfi_exc_action_check_exception_send`**: Debugger'a bir exception message gönderilir
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling (debugging) sırasında label lifecycle
- **`proc_check_get_task`**: Diğer process'lerin process'in task port'unu almasına izin veren `get-task-allow` ve process'in diğer process'lerin task port'larını almasına izin veren `task_for_pid-allow` gibi entitlement'ları kontrol eder. Bunların hiçbiri yoksa izin verilip verilmediğini kontrol etmek için `amfid permitunrestricteddebugging`'e başvurur.
- **`proc_check_mprotect`**: `mprotect`, bölgenin geçerli bir code signature'a sahipmiş gibi ele alınması gerektiğini belirten `VM_PROT_TRUSTED` flag'i ile çağrılırsa reddeder.
- **`vnode_check_exec`**: Executable file'lar memory'ye yüklendiğinde çağrılır ve sayfalardan herhangi biri geçersiz hale gelirse process'i sonlandıracak `cs_hard | cs_kill` değerlerini ayarlar<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` ve `isVnodeQuarantined()` kontrollerini yapar
- **`vnode_check_setextattr`**: `get` ile aynıdır + `com.apple.private.allow-bless` ve `internal-installer-equivalent` entitlement'ı
- **`vnode_check_signature`**: Entitlement'ları, trust cache'i ve `amfid`'yi kullanarak code signature'ı kontrol etmesi için XNU'yu çağıran kod<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` çağrılarını (`PT_ATTACH` ve `PT_TRACE_ME`) intercept eder. `get-task-allow`, `run-invalid-allow` ve `run-unsigned-code` entitlement'larından herhangi birini kontrol eder; hiçbiri yoksa debugging'e izin verilip verilmediğini kontrol eder.
- **`proc_check_map_anon`**: mmap **`MAP_JIT`** flag'i ile çağrılırsa AMFI `dynamic-codesigning` entitlement'ını kontrol eder.

`AMFI.kext`, diğer kernel extension'ların kullanması için bir API de sunar ve bağımlılıklarını şu şekilde bulmak mümkündür:
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

Bu, `AMFI.kext`'in user mode'da code signature'larını kontrol etmek için kullandığı user mode daemon'ıdır.\
`AMFI.kext` daemon ile iletişim kurmak için `HOST_AMFID_PORT` portu üzerinden mach messages kullanır; bu, özel `18` portudur.

macOS'ta root process'lerinin artık özel port'ları hijack etmesinin mümkün olmadığını unutmayın; çünkü bu port'lar `SIP` tarafından korunur ve yalnızca launchd bunlara erişebilir. iOS'ta ise yanıtı gönderen process'in hardcoded `amfid` CDHash'ine sahip olup olmadığı kontrol edilir.

`amfid`'in bir binary'yi kontrol etmesinin ne zaman istendiğini ve verdiği yanıtı, debug ederek ve `mach_msg` içinde breakpoint ayarlayarak görmek mümkündür.

Özel port üzerinden bir message alındığında, her function'ı çağırdığı function'a göndermek için **MIG** kullanılır. Ana function'lar reverse edildi ve kitap içinde açıklandı.

### DYLD policy and library validation

Güncel `dyld` sürümleri, process'in `DYLD_*` path variable'larını, interposing'i, fallback path'lerini veya embedded variable'ları kullanıp kullanamayacağını ya da başarısız library insertion'ı tolere edip edemeyeceğini AMFI'ye sormak için `configureProcessRestrictions()` içinden çok erken bir aşamada `amfi_check_dyld_policy_self()` çağırır. Bu nedenle bir injection surface'i triage ederken yalnızca Mach-O load command'larını incelemek yeterli değildir: AMFI'nin `dyld` policy'ye dönüştüreceği entitlement'ları ve runtime flag'lerini de incelemeniz gerekir.

Pratik bir triage döngüsü şöyledir:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Modern macOS'ta birçok Apple binary'si artık doğrudan `com.apple.security.cs.disable-library-validation` taşımıyor; bunun yerine `com.apple.private.security.clear-library-validation` ile birlikte geliyor. Bu durumda library validation `execve` zamanında devre dışı bırakılmaz: process kendi üzerinde `csops(..., CS_OPS_CLEAR_LV, ...)` çağrısını yapmalıdır ve XNU, entitlement mevcut olduğunda bu işleme yalnızca çağrıyı yapan process üzerinde izin verir. Offensive açıdan bu önemlidir; çünkü bir target, LV'yi açıkça temizleyen code path'e ulaşana kadar injectable olmayabilir (örneğin optional plugin'leri yüklemeden hemen önce).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Bir provisioning profile, code imzalamak için kullanılabilir. Code imzalamak ve test etmek için kullanılabilen **Developer** profilleri ve tüm cihazlarda kullanılabilen **Enterprise** profilleri vardır.

Bir App Apple Store'a gönderildikten ve onaylandıktan sonra Apple tarafından imzalanır ve provisioning profile'a artık ihtiyaç duyulmaz.

Bir profile genellikle `.mobileprovision` veya `.provisionprofile` uzantısını kullanır ve şu şekilde dump edilebilir:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bazen certificated olarak adlandırılsalar da bu provisioning profile'lar bir certificate'tan daha fazlasını içerir:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Bunun bir Apple Internal profile olduğunu belirtir
- **ApplicationIdentifierPrefix**: AppIDName'in başına eklenir (TeamIdentifier ile aynıdır)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında tarih
- **DeveloperCertificates**: Base64 data olarak kodlanmış (genellikle bir) certificate dizisi
- **Entitlements**: Bu profile ile izin verilen entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında expiration date
- **Name**: Application Name; AppIDName ile aynıdır
- **ProvisionedDevices**: Bu profile'ın geçerli olduğu UDID'lerin (developer certificate'lar için) dizisi
- **ProvisionsAllDevices**: Bir boolean (enterprise certificate'lar için true)
- **TeamIdentifier**: Inter-app interaction amaçlarıyla developer'ı tanımlamak için kullanılan (genellikle bir) alfanümerik string dizisi
- **TeamName**: Developer'ı tanımlamak için kullanılan, insanlar tarafından okunabilir ad
- **TimeToLive**: Certificate'ın geçerlilik süresi (gün cinsinden)
- **UUID**: Bu profile için Universally Unique Identifier
- **Version**: Şu anda 1 olarak ayarlanmıştır

Entitlements girdisinin kısıtlı bir entitlements kümesi içereceğini ve Apple private entitlements'larının verilmesini önlemek amacıyla provisioning profile'ın yalnızca bu belirli entitlements'ları sağlayabileceğini unutmayın.

Profile'lar genellikle `/var/MobileDeviceProvisioningProfiles` konumunda bulunur ve **`security cms -D -i /path/to/profile`** ile kontrol edilebilir.

## **libmis.dylib**

Bu, `amfid`'nin bir şeye izin verip vermemesi gerektiğini sormak için çağırdığı external library'dir. Tarihsel olarak jailbreaking kapsamında, her şeye izin veren backdoored bir sürümü çalıştırılarak kötüye kullanılmıştır.

macOS'ta bu library `MobileDevice.framework` içinde bulunur.

## AMFI Trust Caches

Trust caches yalnızca iOS'a özgü bir kavram değildir. Modern macOS'ta, özellikle **Apple silicon** üzerinde, static trust cache ve loadable trust caches Secure Boot chain'in parçalarıdır. Bir Mach-O'nun **CodeDirectory hash** değeri burada mevcutsa AMFI, launch sırasında başka authenticity kontrolleri yapmadan ona **platform privilege** verebilir. Bu aynı zamanda Apple'ın platform binary'lerini belirli bir OS version'a kilitlemesine ve daha eski Apple-signed binary'lerin daha yeni sistemlerde yeniden kullanılmasını önlemesine olanak tanır.<sup>[[6]](#references)</sup>

Yeni macOS sürümlerinde trust-cache metadata'sı **launch constraints** ile de ilişkilendirilir. Bu nedenle kopyalanmış system app'leri ve binary'ler, hâlâ Apple-signed olsalar bile yanlış parent/location'dan başlatıldıklarında AMFI tarafından reddedilebilir. Ayrıntılı extraction ve reversing workflow'u şu belgede ele alınmaktadır:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS ve jailbreak araştırmalarında, ad-hoc signed binary'leri whitelist etmek için kullanılan geleneksel **loadable trust caches** modeline hâlâ rastlayabilirsiniz.

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
