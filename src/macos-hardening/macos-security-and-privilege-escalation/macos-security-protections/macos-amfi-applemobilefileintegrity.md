# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext ve amfid

Sistemde çalışan kodun bütünlüğünü zorunlu kılmaya odaklanır ve XNU'nun code signature doğrulamasının arkasındaki mantığı sağlar. Ayrıca entitlements'ları kontrol edebilir ve debugging'e izin verme veya task port'ları elde etme gibi diğer hassas görevleri gerçekleştirebilir.

Bunun yanı sıra, bazı işlemler için kext, user space'te çalışan `/usr/libexec/amfid` daemon'ı ile iletişim kurmayı tercih eder. Bu trust relationship, çeşitli jailbreak'lerde kötüye kullanılmıştır.

Güncel macOS sürümlerinde AMFI artık bağımsız bir on-disk kext olarak uygun şekilde sunulmadığından, reversing işlemi genellikle `/System/Library/Extensions` dizinine göz atmak yerine **kernelcache** veya bir **KDK** üzerinden çalışmayı gerektirir.

AMFI, **MACF** policies kullanır ve başlatıldığı anda hook'larını kaydeder. Ayrıca yüklenmesini engellemek veya unload etmek kernel panic'i tetikleyebilir. Bununla birlikte AMFI'yi devre dışı bırakmaya izin veren bazı boot arguments vardır:

- `amfi_unrestricted_task_for_pid`: Gerekli entitlements olmadan task_for_pid kullanımına izin verir
- `amfi_allow_any_signature`: Herhangi bir code signature'a izin verir
- `cs_enforcement_disable`: Code signing enforcement'ı sistem genelinde devre dışı bırakmak için kullanılan argument
- `amfi_prevent_old_entitled_platform_binaries`: Entitlements içeren platform binaries'lerini geçersiz kılar
- `amfi_get_out_of_my_way`: amfi'yi tamamen devre dışı bırakır

Kaydettiği MACF policies'lerden bazıları şunlardır:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update gerçekleştirilir ve 1 döndürülür
- **`cred_label_associate`**: AMFI'nin mac label slot'unu label ile günceller
- **`cred_label_destroy`**: AMFI'nin mac label slot'unu kaldırır
- **`cred_label_init`**: AMFI'nin mac label slot'una 0 taşır
- **`cred_label_update_execve`:** Process'in labels'ı değiştirmesine izin verilip verilmediğini görmek için entitlements'larını kontrol eder.
- **`file_check_mmap`:** mmap'in memory edinip onu executable olarak ayarlayıp ayarlamadığını kontrol eder. Bu durumda library validation gerekip gerekmediğini kontrol eder ve gerekiyorsa library validation function'ı çağırır.
- **`file_check_library_validation`**: Diğer şeylerin yanı sıra bir platform binary'sinin başka bir platform binary'si yükleyip yüklemediğini veya process ile yeni yüklenen file'ın aynı TeamID'ye sahip olup olmadığını kontrol eden library validation function'ı çağırır. Belirli entitlements'lar herhangi bir library'nin yüklenmesine de izin verir.
- **`policy_initbsd`**: Trusted NVRAM Keys'i ayarlar
- **`policy_syscall`**: Binary'nin unrestricted segments'a sahip olup olmadığı, env vars'lara izin verilip verilmeyeceği gibi DYLD policies'leri kontrol eder... Bu ayrıca bir process `amfi_check_dyld_policy_self()` üzerinden başlatıldığında da çağrılır.
- **`proc_check_inherit_ipc_ports`**: Bir process yeni bir binary çalıştırdığında, process'in task port'u üzerinde SEND rights'a sahip diğer process'lerin bu hakları koruyup korumaması gerektiğini kontrol eder. Platform binaries'lerine izin verilir, `get-task-allow` entitled olanlara izin verilir, `task_for_pid-allow` entitlements'larına izin verilir ve aynı TeamID'ye sahip binaries'lere izin verilir.
- **`proc_check_expose_task`**: Entitlements'ları zorunlu kılar
- **`amfi_exc_action_check_exception_send`**: Debugger'a bir exception message gönderilir
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling (debugging) sırasında label lifecycle
- **`proc_check_get_task`**: Diğer process'lerin task port'unu almasına izin veren `get-task-allow` ve process'in diğer process'lerin task port'larını almasına izin veren `task_for_pid-allow` gibi entitlements'ları kontrol eder. Bunların hiçbiri yoksa, izin verilip verilmediğini kontrol etmek için `amfid permitunrestricteddebugging`'i çağırır.
- **`proc_check_mprotect`**: `mprotect`, bölgenin geçerli bir code signature'a sahipmiş gibi ele alınması gerektiğini belirten `VM_PROT_TRUSTED` flag'i ile çağrılırsa reddeder.
- **`vnode_check_exec`**: Executable files memory'ye yüklendiğinde çağrılır ve sayfalardan herhangi biri geçersiz hâle gelirse process'i sonlandıracak `cs_hard | cs_kill` ayarını yapar<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` ve `isVnodeQuarantined()`'ı kontrol eder
- **`vnode_check_setextattr`**: `get` ile aynıdır + `com.apple.private.allow-bless` ve `internal-installer-equivalent` entitlement'ı
- **`vnode_check_signature`**: Entitlements, trust cache ve `amfid` kullanarak code signature'ı kontrol etmek üzere XNU'yu çağıran kod<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` çağrılarını (`PT_ATTACH` ve `PT_TRACE_ME`) intercept eder. `get-task-allow`, `run-invalid-allow` ve `run-unsigned-code` entitlements'larından herhangi birini kontrol eder; hiçbiri yoksa debugging'e izin verilip verilmediğini kontrol eder.
- **`proc_check_map_anon`**: mmap **`MAP_JIT`** flag'i ile çağrılırsa AMFI `dynamic-codesigning` entitlement'ını kontrol eder.

`AMFI.kext` ayrıca diğer kernel extensions için bir API sunar ve dependencies'lerini şu şekilde bulmak mümkündür:
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

Bu, `AMFI.kext`'in code signatures'ı user mode'da kontrol etmek için kullandığı user mode daemon'ıdır.\
`AMFI.kext` daemon ile iletişim kurmak için `HOST_AMFID_PORT` portu üzerinden mach messages kullanır; bu, özel port `18`'dir.

macOS'ta root process'lerinin özel portları hijack etmesi artık mümkün değildir; çünkü bu portlar `SIP` tarafından korunur ve yalnızca launchd bunları alabilir. iOS'ta ise yanıtı gönderen process'in hardcoded `amfid` CDHash'ine sahip olduğu kontrol edilir.

`amfid`'in bir binary'yi kontrol etmesi istendiğinde ve verdiği yanıtı, debugging yaparak ve `mach_msg` içinde bir breakpoint ayarlayarak görmek mümkündür.

Özel port üzerinden bir message alındığında, her function'ı çağrıldığı function'a göndermek için **MIG** kullanılır. Ana function'lar reverse edildi ve kitap içinde açıklandı.

### DYLD policy ve library validation

Recent `dyld` versions, process'in `DYLD_*` path variables, interposing, fallback paths veya embedded variables kullanıp kullanamayacağını ya da başarısız library insertion'ı tolere edip edemeyeceğini AMFI'ye sormak için `configureProcessRestrictions()` içinden çok erken bir aşamada `amfi_check_dyld_policy_self()` çağırır. Bu nedenle bir injection surface'ini triage ederken yalnızca Mach-O load commands'larını incelemek yeterli değildir: AMFI'nin `dyld` policy'ye dönüştüreceği entitlements ve runtime flags'leri de incelemeniz gerekir.

Pratik bir triage loop şu şekildedir:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Modern macOS'ta birçok Apple binary'si artık `com.apple.security.cs.disable-library-validation` değerini doğrudan taşımaz; bunun yerine `com.apple.private.security.clear-library-validation` ile gelir. Bu durumda library validation, `execve` zamanında devre dışı bırakılmaz: process kendi üzerinde `csops(..., CS_OPS_CLEAR_LV, ...)` çağrısı yapmalıdır ve XNU bu işleme yalnızca entitlement mevcut olduğunda çağrıyı yapan process üzerinde izin verir. Offensive açıdan bunun önemi, bir target'ın yalnızca açıkça LV'yi temizleyen code path'e ulaştıktan sonra injectable hâle gelebilmesidir (örneğin optional plugin'leri yüklemeden kısa süre önce).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profilleri

Bir provisioning profile, code sign etmek için kullanılabilir. Code sign edip test etmek için kullanılabilen **Developer** profilleri ve tüm cihazlarda kullanılabilen **Enterprise** profilleri vardır.

Bir App Apple Store'a gönderildikten sonra onaylanırsa Apple tarafından sign edilir ve provisioning profile'a artık ihtiyaç kalmaz.

Bir profile genellikle `.mobileprovision` veya `.provisionprofile` extension'ı verilir ve şu komutla dump edilebilir:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bazen certificated olarak adlandırılsalar da bu provisioning profilleri bir sertifikadan daha fazlasını içerir:

- **AppIDName:** Uygulama tanımlayıcısı
- **AppleInternalProfile**: Bunun bir Apple Internal profili olduğunu belirtir
- **ApplicationIdentifierPrefix**: AppIDName'in başına eklenir (TeamIdentifier ile aynıdır)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` biçiminde tarih
- **DeveloperCertificates**: Base64 verisi olarak kodlanmış, genellikle tek bir sertifika içeren dizi
- **Entitlements**: Bu profil için entitlements ile izin verilen entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` biçiminde son kullanma tarihi
- **Name**: AppIDName ile aynı olan uygulama adı
- **ProvisionedDevices**: Bu profilin geçerli olduğu UDID'lerden oluşan dizi (developer sertifikaları için)
- **ProvisionsAllDevices**: Bir boolean (enterprise sertifikaları için true)
- **TeamIdentifier**: Uygulamalar arası etkileşim amacıyla geliştiriciyi tanımlamak için kullanılan, genellikle tek bir alfasayısal string içeren dizi
- **TeamName**: Geliştiriciyi tanımlamak için kullanılan, insanlar tarafından okunabilir ad
- **TimeToLive**: Sertifikanın geçerlilik süresi (gün olarak)
- **UUID**: Bu profil için Evrensel Olarak Benzersiz Tanımlayıcı
- **Version**: Şu anda 1 olarak ayarlanmıştır

Entitlements girdisinin kısıtlı bir entitlements kümesi içereceğini ve Apple private entitlements'ın verilmesini önlemek amacıyla provisioning profilinin yalnızca bu belirli entitlements'ları sağlayabileceğini unutmayın.

Profiller genellikle `/var/MobileDeviceProvisioningProfiles` konumunda bulunur ve **`security cms -D -i /path/to/profile`** ile kontrol edilebilir.

## **libmis.dylib**

Bu, `amfid`'in bir şeye izin verip vermemesi gerektiğini sormak için çağırdığı harici kütüphanedir. Tarihsel olarak jailbreaking işleminde, her şeye izin veren backdoored bir sürümü çalıştırılarak kötüye kullanılmıştır.

macOS'ta bu kütüphane `MobileDevice.framework` içindedir.

## AMFI Trust Caches

Trust cache'ler yalnızca bir iOS kavramı değildir. Modern macOS'ta, özellikle **Apple silicon** üzerinde, static trust cache ve loadable trust cache'ler Secure Boot zincirinin parçalarıdır. Bir Mach-O'nun **CodeDirectory hash** değeri burada mevcutsa AMFI, launch sırasında ek authenticity kontrolleri yapmadan ona **platform privilege** verebilir. Bu aynı zamanda Apple'ın platform binary'lerini belirli bir OS sürümüne kilitlemesine ve daha eski Apple-signed binary'lerin daha yeni sistemlerde replay edilmesini önlemesine olanak tanır.<sup>[[6]](#references)</sup>

Son macOS sürümlerinde trust-cache metadata'sı **launch constraints** ile de ilişkilendirilmiştir. Bu nedenle kopyalanmış system app'leri ve binary'ler, hâlâ Apple-signed olsalar bile yanlış parent/location üzerinden başlatıldıklarında AMFI tarafından reddedilebilir. Ayrıntılı extraction ve reversing workflow'u şu belgede ele alınmaktadır:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS ve jailbreak araştırmalarında, ad-hoc signed binary'leri whitelist etmek için kullanılan geleneksel **loadable trust caches** modelini hâlâ görebilirsiniz.

## References

- [1] [XNU — `security/mac_policy.h` (AMFI'nin kaydettiği MACF policy ops; `mpo_policy_syscall` dahil)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (AMFI'nin ayarladığı `CS_*` code-signing flag'leri)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing ve validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` işlemleri ve `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler'ı)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
