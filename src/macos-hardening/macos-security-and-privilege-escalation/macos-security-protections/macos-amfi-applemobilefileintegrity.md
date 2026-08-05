# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext ve amfid

Sistemde çalışan kodun bütünlüğünü zorunlu kılmaya odaklanır ve XNU'nun code signature doğrulamasının arkasındaki mantığı sağlar. Ayrıca entitlements'ları kontrol edebilir ve debugging'e izin verme veya task port'ları elde etme gibi diğer hassas görevleri gerçekleştirebilir.

Bunun yanı sıra kext, bazı işlemler için user space'te çalışan `/usr/libexec/amfid` daemon'ı ile iletişim kurmayı tercih eder. Bu güven ilişkisi çeşitli jailbreak'lerde abuse edilmiştir.

Güncel macOS sürümlerinde AMFI artık disk üzerinde bağımsız bir kext olarak kolayca sunulmamaktadır; bu nedenle reversing genellikle `/System/Library/Extensions` dizinine göz atmak yerine **kernelcache** veya **KDK** üzerinden çalışmayı gerektirir.

AMFI, **MACF** policies kullanır ve başlatıldığı anda hook'larını kaydeder. Ayrıca yüklenmesini engellemek veya yükünü kaldırmak kernel panic'i tetikleyebilir. Bununla birlikte AMFI'yi devre dışı bırakmaya olanak tanıyan bazı boot arguments vardır:

- `amfi_unrestricted_task_for_pid`: Gerekli entitlements olmadan task_for_pid kullanımına izin verir
- `amfi_allow_any_signature`: Herhangi bir code signature'a izin verir
- `cs_enforcement_disable`: Code signing enforcement'ı sistem genelinde devre dışı bırakmak için kullanılan argument
- `amfi_prevent_old_entitled_platform_binaries`: Entitlements içeren platform binaries'lerini geçersiz kılar
- `amfi_get_out_of_my_way`: amfi'yi tamamen devre dışı bırakır

Bunlar, kaydettiği MACF policies'lerinden bazılarıdır:<sup>[1]</sup>

- **`cred_check_label_update_execve:`** Label güncellemesi gerçekleştirilir ve 1 döndürülür
- **`cred_label_associate`**: AMFI'nin mac label slot'unu label ile günceller
- **`cred_label_destroy`**: AMFI'nin mac label slot'unu kaldırır
- **`cred_label_init`**: AMFI'nin mac label slot'una 0 taşır
- **`cred_label_update_execve:`**:** Process'in label'ları değiştirmesine izin verilip verilmediğini görmek için entitlements'larını kontrol eder.
- **`file_check_mmap:`**:** mmap'in memory elde edip bunu executable olarak ayarlayıp ayarlamadığını kontrol eder. Bu durumda library validation gerekip gerekmediğini kontrol eder ve gerekiyorsa library validation function'ı çağırır.
- **`file_check_library_validation`**: Diğer şeylerin yanı sıra bir platform binary'sinin başka bir platform binary'si yükleyip yüklemediğini veya process ile yeni yüklenen file'ın aynı TeamID'ye sahip olup olmadığını kontrol eden library validation function'ı çağırır. Belirli entitlements'lar herhangi bir library'nin yüklenmesine de izin verir.
- **`policy_initbsd`**: Trusted NVRAM Keys'i ayarlar
- **`policy_syscall`**: Binary'nin unrestricted segments'lara sahip olup olmadığı veya env vars'a izin verilip verilmemesi gibi DYLD policies'lerini kontrol eder; bu ayrıca bir process `amfi_check_dyld_policy_self()` aracılığıyla başlatıldığında da çağrılır.
- **`proc_check_inherit_ipc_ports`**: Bir process yeni bir binary execute ettiğinde, process'in task port'u üzerinde SEND rights sahibi diğer process'lerin bunları koruyup korumaması gerektiğini kontrol eder. Platform binaries'lerine izin verilir, `get-task-allow` entitle'ına sahip olanlara izin verilir, `task_for_pid-allow` entitlements'larına izin verilir ve aynı TeamID'ye sahip binary'lere izin verilir.
- **`proc_check_expose_task`**: Entitlements'ları enforce eder
- **`amfi_exc_action_check_exception_send`**: Debugger'a bir exception message gönderilir
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Exception handling (debugging) sırasında label lifecycle
- **`proc_check_get_task`**: Diğer process'lerin task port'unu elde etmesine izin veren `get-task-allow` ve process'in diğer process'lerin task port'larını elde etmesine izin veren `task_for_pid-allow` gibi entitlements'ları kontrol eder. Bunların hiçbiri yoksa izin verilip verilmediğini kontrol etmek için `amfid permitunrestricteddebugging`'e kadar çağrı yapar.
- **`proc_check_mprotect`**: Bölgenin geçerli bir code signature'a sahipmiş gibi ele alınması gerektiğini belirten `VM_PROT_TRUSTED` flag'i ile `mprotect` çağrılırsa reddeder.
- **`vnode_check_exec`**: Executable files memory'ye yüklendiğinde çağrılır ve sayfalardan herhangi biri geçersiz hale gelirse process'i öldürecek `cs_hard | cs_kill` değerlerini ayarlar<sup>[2]</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` ve `isVnodeQuarantined()` kontrol edilir
- **`vnode_check_setextattr`**: `get` işlemi ile aynıdır; ayrıca `com.apple.private.allow-bless` ve `internal-installer-equivalent` entitlement'ını gerektirir
- **`vnode_check_signature`**: Entitlements, trust cache ve `amfid` kullanarak code signature'ı kontrol etmek için XNU'yu çağıran code<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` çağrılarını (`PT_ATTACH` ve `PT_TRACE_ME`) intercept eder. `get-task-allow`, `run-invalid-allow` ve `run-unsigned-code` entitlements'larından herhangi birini kontrol eder; hiçbiri yoksa debugging'e izin verilip verilmediğini kontrol eder.
- **`proc_check_map_anon`**: mmap **`MAP_JIT`** flag'i ile çağrılırsa AMFI, `dynamic-codesigning` entitlement'ını kontrol eder.

`AMFI.kext`, diğer kernel extensions'lar için de bir API sunar ve dependencies'lerini şu şekilde bulmak mümkündür:
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

Bu, `AMFI.kext`'in kullanıcı modunda code signature'ları kontrol etmek için kullandığı user mode daemon'ıdır.\
`AMFI.kext`'in daemon ile iletişim kurabilmesi için `HOST_AMFID_PORT` portu üzerinden Mach mesajlarını kullanır; bu, özel `18` portudur.

macOS'ta root process'lerinin artık özel portları hijack etmesinin mümkün olmadığını unutmayın; çünkü bu portlar `SIP` tarafından korunur ve bunlara yalnızca launchd erişebilir. iOS'ta ise yanıtı gönderen process'in `amfid`'in hardcoded CDHash'ine sahip olduğu kontrol edilir.

`amfid`'den bir binary'yi kontrol etmesi istendiğinde ve yanıt verdiğinde, debug ederek ve `mach_msg` içinde breakpoint ayarlayarak bunu görmek mümkündür.

Özel port üzerinden bir mesaj alındığında, her function'ı çağırdığı function'a göndermek için **MIG** kullanılır. Ana function'lar reverse edildi ve book içinde açıklandı.

### DYLD policy ve library validation

Recent `dyld` sürümleri, process'in `DYLD_*` path variable'larını, interposing'i, fallback path'lerini veya embedded variable'ları kullanıp kullanamayacağını ya da başarısız library insertion'larını tolere edip edemeyeceğini AMFI'ye sormak için `configureProcessRestrictions()` içinden çok erken bir aşamada `amfi_check_dyld_policy_self()` function'ını çağırır. Bu nedenle bir injection surface'i triage ederken yalnızca Mach-O load command'larını incelemek yeterli değildir: AMFI'nin `dyld` policy'ye dönüştüreceği entitlement'ları ve runtime flag'lerini de incelemeniz gerekir.

Pratik bir triage döngüsü şöyledir:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Modern macOS'te birçok Apple binary'si artık `com.apple.security.cs.disable-library-validation` değerini doğrudan taşımıyor; bunun yerine `com.apple.private.security.clear-library-validation` ile geliyor. Bu durumda library validation `execve` zamanında devre dışı bırakılmaz: process'in kendi üzerinde `csops(..., CS_OPS_CLEAR_LV, ...)` çağrısı yapması gerekir ve XNU, entitlement mevcut olduğunda bu işleme yalnızca çağrıyı yapan process üzerinde izin verir. Offensive açıdan bu önemlidir; çünkü bir hedef, LV'yi açıkça temizleyen code path'e ulaşana kadar injectable hale gelmeyebilir (örneğin optional plugin'leri yüklemeden hemen önce).<sup>[4][5]</sup>

## Provisioning Profiles

Bir provisioning profile, code imzalamak için kullanılabilir. Code'u imzalamak ve test etmek için kullanılabilen **Developer** profilleri ve tüm cihazlarda kullanılabilen **Enterprise** profilleri vardır.

Bir App Apple Store'a gönderildikten ve onaylandıktan sonra Apple tarafından imzalanır ve provisioning profile artık gerekli olmaz.

Bir profile genellikle `.mobileprovision` veya `.provisionprofile` extension'ına sahiptir ve şu komutla dump edilebilir:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bazen sertifikalı olarak adlandırılsalar da bu provisioning profile'lar bir sertifikadan daha fazlasını içerir:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Bunun bir Apple Internal profile olduğunu belirtir
- **ApplicationIdentifierPrefix**: AppIDName'in önüne eklenir (TeamIdentifier ile aynıdır)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında tarih
- **DeveloperCertificates**: Base64 data olarak kodlanmış (genellikle bir) sertifika dizisi
- **Entitlements**: Bu profile için izin verilen entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` formatında sona erme tarihi
- **Name**: Application Name; AppIDName ile aynıdır
- **ProvisionedDevices**: Bu profile'ın geçerli olduğu UDID'lerin (developer certificate'ları için) bir dizisi
- **ProvisionsAllDevices**: Bir boolean (enterprise certificate'ları için true)
- **TeamIdentifier**: Inter-app interaction amaçları doğrultusunda developer'ı tanımlamak için kullanılan (genellikle bir) alfanümerik string dizisi
- **TeamName**: Developer'ı tanımlamak için kullanılan, insanlar tarafından okunabilir ad
- **TimeToLive**: Certificate'ın geçerlilik süresi (gün cinsinden)
- **UUID**: Bu profile için Universally Unique Identifier
- **Version**: Şu anda 1 olarak ayarlanmıştır

Entitlements girdisinin kısıtlı bir entitlements kümesi içereceğini ve provisioning profile'ın, Apple private entitlements'ın verilmesini önlemek için yalnızca bu belirli entitlements'ı sağlayabileceğini unutmayın.

Profile'ların genellikle `/var/MobileDeviceProvisioningProfiles` konumunda bulunduğunu ve **`security cms -D -i /path/to/profile`** ile kontrol edilebileceğini unutmayın.

## **libmis.dylib**

Bu, bir şeye izin verip vermemesi gerektiğini sormak için `amfid` tarafından çağrılan external library'dir. Geçmişte jailbreaking sürecinde, her şeye izin veren backdoored bir sürümü çalıştırılarak kötüye kullanılmıştır.

macOS'ta bu library `MobileDevice.framework` içinde bulunur.

## AMFI Trust Caches

Trust cache'ler yalnızca iOS'a özgü bir kavram değildir. Modern macOS'ta, özellikle **Apple silicon** üzerinde, static trust cache ve loadable trust cache'ler Secure Boot zincirinin bir parçasıdır. Bir Mach-O'nun **CodeDirectory hash** değeri burada mevcutsa AMFI, launch sırasında ek authenticity kontrolleri yapmadan ona **platform privilege** verebilir. Bu ayrıca Apple'ın platform binary'lerini belirli bir OS sürümüne kilitlemesine ve daha eski Apple-signed binary'lerin daha yeni sistemlerde replay edilmesini önlemesine olanak tanır.<sup>[6]</sup>

Yeni macOS sürümlerinde trust-cache metadata'sı ayrıca **launch constraints** ile ilişkilidir. Bu nedenle kopyalanmış system app'leri ve binary'ler hâlâ Apple-signed olsalar bile yanlış parent/location'dan başlatıldıklarında AMFI tarafından reddedilebilir. Ayrıntılı extraction ve reversing workflow'u şurada ele alınmaktadır:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS ve jailbreak araştırmalarında, ad-hoc signed binary'leri whitelist etmek için kullanılan geleneksel **loadable trust cache** modeline hâlâ rastlarsınız.

## References

- [1] [XNU — `security/mac_policy.h` (AMFI'nin kaydettiği MACF policy ops; `mpo_policy_syscall` dahil)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (AMFI'nin ayarladığı `CS_*` code-signing flag'leri)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing ve validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations ve `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler'ı)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust cache'ler](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
