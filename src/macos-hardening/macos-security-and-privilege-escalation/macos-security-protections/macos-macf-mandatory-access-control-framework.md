# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**MACF**, bilgisayarınızı korumaya yardımcı olmak üzere işletim sistemine yerleşik bir güvenlik sistemi olan **Mandatory Access Control Framework** ifadesinin kısaltmasıdır. Dosyalar, uygulamalar ve sistem kaynakları gibi sistemin belirli bölümlerine kimlerin veya nelerin erişebileceği konusunda **katı kurallar** belirleyerek çalışır. Bu kuralları otomatik olarak uygulayan MACF, yalnızca yetkili kullanıcıların ve process'lerin belirli işlemleri gerçekleştirebilmesini sağlayarak yetkisiz erişim veya malicious faaliyet riskini azaltır.

MACF'nin aslında herhangi bir karar vermediğini unutmayın; yalnızca eylemleri **intercept** eder ve kararları `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` ve `mcxalr.kext` gibi çağırdığı **policy modules**'lara (kernel extensions) bırakır.

- Bir policy enforcing olabilir (bazı işlemlerde 0 dışı bir değer döndürür)
- Bir policy monitoring yapabilir (itiraz etmemek, ancak bir şey yapmak için hook'tan yararlanmak amacıyla 0 döndürür)
- Bir MACF static policy boot sırasında yüklenir ve ASLA kaldırılmaz
- Bir MACF dynamic policy bir KEXT tarafından (kextload) yüklenir ve teorik olarak kextunload edilebilir
- iOS'ta yalnızca static policy'lere, macOS'ta ise static + dynamic policy'lere izin verilir.<sup>[[7]](#references)</sup>

### Akış

1. Process bir syscall/mach trap gerçekleştirir
2. Kernel içinde ilgili function çağrılır
3. Function MACF'yi çağırır
4. MACF, policy'lerinde bu function'a hook eklenmesini talep eden policy modules'ları kontrol eder
5. MACF ilgili policy'leri çağırır
6. Policy'ler eyleme izin verip vermediklerini belirtir

> [!CAUTION]
> MAC Framework KPI'yi kullanabilen tek kuruluş Apple'dır.

Genellikle MACF ile permission'ları kontrol eden function'lar `MAC_CHECK` macro'sunu çağırır. Bir socket oluşturmak için gerçekleştirilen syscall örneğinde olduğu gibi; bu syscall, `mac_socket_check_create` function'ını çağırır ve bu function da `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` çağrısını yapar. Ayrıca `MAC_CHECK` macro'su security/mac_internal.h içinde şu şekilde tanımlanır:<sup>[[3]](#references)</sup>
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
`check` ifadesini `socket_check_create` ve `args...` ifadesini `(cred, domain, type, protocol)` olarak dönüştürdüğünüzde şunu elde edersiniz:
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Yardımcı makrolar genişletildiğinde somut kontrol akışı ortaya çıkar:
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
Başka bir deyişle, `MAC_CHECK(socket_check_create, ...)` önce statik policy'leri işler, ardından koşullu olarak kilitler ve dinamik policy'ler üzerinde yineleme yapar, her hook'un etrafında DTrace probe'larını üretir ve her hook'un dönüş kodunu `mac_error_select()` aracılığıyla tek bir `error` sonucunda birleştirir.


### Etiketler

MACF, erişim izni verilip verilmeyeceğini kontrol eden policy'lerin kullanacağı **etiketleri** kullanır. Etiket struct'ının bildirim kodu [burada bulunabilir](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h); bu struct daha sonra [buradaki](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`struct ucred`** içinde **`cr_label`** bölümünde kullanılır. Etiket, flag'ler ve **MACF policy'lerinin pointer ayırmak** için kullanabileceği bir dizi **slot** içerir. Örneğin Sanbox, container profile'ını gösterir.

## MACF Politikaları

Bir MACF Policy, belirli kernel işlemlerinde uygulanacak **kural ve koşulları** tanımlar.

Bir kernel extension, `mac_policy_conf` struct'ını yapılandırabilir ve ardından `mac_policy_register` çağrısıyla kaydedebilir. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered entry-point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
Bu politikaları yapılandıran kernel extension'ları, `mac_policy_register` çağrılarını kontrol ederek kolayca belirlemek mümkündür. Ayrıca extension'ın disassemble çıktısını kontrol ederek kullanılan `mac_policy_conf` struct'ını bulmak da mümkündür.

MACF politikalarının **dinamik olarak** kaydedilip kaydı silinebileceğini unutmayın.

`mac_policy_conf` struct'ının ana alanlarından biri **`mpc_ops`**'tir. Bu alan, politikanın hangi işlemlerle ilgilendiğini belirtir. Bunlardan yüzlerce tane vardır; bu nedenle tüm girdileri sıfırlayıp yalnızca politikanın ihtiyaç duyduklarını seçmek mümkündür. [Buradan](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
Neredeyse tüm hook'lar, bu operasyonlardan biri intercept edildiğinde MACF tarafından callback ile çağrılır. Ancak **`mpo_policy_*`** hook'ları bir istisnadır; çünkü **`mpo_hook_policy_init()`**, registration sırasında çağrılan bir callback'tir (yani `mac_policy_register()` sonrasında), **`mpo_hook_policy_initbsd()`** ise BSD subsystem düzgün şekilde initialize olduktan sonra late registration sırasında çağrılır.

Ayrıca **`mpo_policy_syscall`** hook'ı, herhangi bir kext tarafından private **ioctl** style call **interface** sunmak için register edilebilir. Böylece bir user client, parametre olarak **policy name**, integer bir **code** ve isteğe bağlı **arguments** belirterek `mac_syscall` (#381) çağırabilir.\
Örneğin **`Sandbox.kext`** bunu oldukça sık kullanır.

Policy register edilirken kullanılan `mac_policy_ops` structure'ını belirlemek için kext'in **`__DATA.__const*`** alanını incelemek mümkündür. Bu structure'ı bulmak mümkündür; çünkü pointer'ı `mpo_policy_conf` içinde bir offset'te bulunur ve ayrıca bu alanda bulunacak NULL pointer'ların miktarı da yardımcı olur.

Ayrıca bir policy configure etmiş kext'lerin listesini, register edilen her policy ile güncellenen **`_mac_policy_list`** struct'ını memory'den dump ederek elde etmek de mümkündür.

System'de register edilmiş tüm policy'leri dump etmek için `xnoop` tool'unu da kullanabilirsiniz:
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
Ve ardından check policy kapsamındaki tüm kontrolleri şu şekilde dökün:
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## XNU'da MACF başlatması

### Erken bootstrap ve mac_policy_init()

- MACF çok erken başlatılır. XNU, `bootstrap_thread` içinde (XNU başlangıç kodunda), `ipc_bootstrap` sonrasında `mac_policy_init()` işlevini (mac_base.c içinde) çağırır.
- `mac_policy_init()`, global `mac_policy_list` yapısını (policy slot'larından oluşan bir dizi veya liste) başlatır ve XNU içindeki MAC (Mandatory Access Control) altyapısını kurar.
- Daha sonra, yerleşik veya bundled policy'lerin kernel tarafındaki kayıt işlemlerini yöneten `mac_policy_initmach()` çağrılır.

### `mac_policy_initmach()` ve “security extensions” yüklenmesi

- `mac_policy_initmach()`, önceden yüklenmiş (veya bir “policy injection” listesinde bulunan) kernel extension'ları (kext'leri) inceler ve bunların Info.plist dosyalarında `AppleSecurityExtension` anahtarını arar.
- Info.plist dosyalarında `<key>AppleSecurityExtension</key>` (veya `true`) tanımlayan kext'ler, “security extensions” olarak değerlendirilir; yani bir MAC policy uygulayan veya MACF altyapısına hook ekleyen kext'lerdir.
- Bu anahtara sahip Apple kext'lerine **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** ve diğerleri örnek verilebilir (daha önce listelediğiniz gibi).
- Kernel, bu kext'lerin erken yüklenmesini sağlar, ardından boot sırasında kayıt rutinlerini (`mac_policy_register` aracılığıyla) çağırarak bunları `mac_policy_list` içine ekler.

- Her policy modülü (kext), çeşitli MAC işlemleri için hook'lar (`mpc_ops`) içeren bir `mac_policy_conf` yapısı sağlar (vnode kontrolleri, exec kontrolleri, label güncellemeleri vb.).
- Yükleme zamanı flag'leri, “erken yüklenmesi zorunlu” anlamına gelen `MPC_LOADTIME_FLAG_NOTLATE` değerini içerebilir (bu durumda geç kayıt girişimleri reddedilir).
- Kayıt tamamlandıktan sonra her modül bir handle alır ve `mac_policy_list` içinde bir slot işgal eder.
- Daha sonra bir MAC hook çağrıldığında (örneğin vnode erişimi, exec vb.), MACF ortak karar vermek için kayıtlı tüm policy'leri dolaşır.

- Özellikle **AMFI** (Apple Mobile File Integrity) böyle bir security extension'dır. Info.plist dosyasında, onu bir security policy olarak işaretleyen `AppleSecurityExtension` bulunur.
- Kernel boot sürecinin bir parçası olarak kernel yükleme mantığı, “security policy”nin (AMFI vb.) birçok subsystem ona ihtiyaç duymadan önce etkin olmasını sağlar. Örneğin kernel, “AppleMobileFileIntegrity (AMFI), Sandbox ve Quarantine policy dahil olmak üzere … security policy'yi yükleyerek görevler için hazırlanır.”
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## MAC policy kext'lerinde KPI bağımlılığı ve com.apple.kpi.dsep

MAC framework'ünü kullanan bir kext yazarken (ör. `mac_policy_register()` çağırırken), kext linker'ın (kxld) bu sembolleri çözebilmesi için KPI'lara (Kernel Programming Interfaces) bağımlılıkları bildirmeniz gerekir. Bu nedenle bir `kext`'in MACF'ye bağımlı olduğunu belirtmek için bunu `Info.plist` içinde `com.apple.kpi.dsep` ile belirtmeniz gerekir (`find . Info.plist | grep AppleSecurityExtension`). Ardından kext; `mac_policy_register`, `mac_policy_unregister` ve MAC hook function pointer'ları gibi sembollere başvurur. Bunları çözümlemek için `com.apple.kpi.dsep`'i bir bağımlılık olarak listelemelisiniz.

Örnek Info.plist parçası (.kext dosyanızın içinde):
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## Modern macOS sürümlerinde MACF

Modern macOS'ta Apple security policies genellikle bağımsız, gevşek `.kext` bundle'ları olarak ele alınmamalıdır. **macOS 11**'den beri kernel extensions, **kernel collections** içine linklenir; **Apple Silicon** üzerinde ayrı bir **SystemKC** yoktur ve third-party kext'ler yalnızca **Auxiliary Kernel Collection (AuxKC)** içine build edildikten ve yeniden başlatma yapıldıktan sonra yüklenebilir hâle gelir. MACF araştırması açısından bu, **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** veya **Quarantine** gibi yerleşik policy'leri, `kextstat` gibi kullanımdan kaldırılmış araçlar yerine genellikle `kmutil` ile enumerate etmenin daha kolay olduğu anlamına gelir.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon'da bir security kext BootKC içinde değilse, sonraki olarak AuxKC'yi kontrol edin. Bu, `/System/Library/Extensions` altında standalone bir bundle aramaktan genellikle daha kullanışlıdır.

## MACF Callouts

MACF'ye yapılan callout'ların şu tür kodlarda tanımlanmış olması yaygındır: **`#if CONFIG_MAC`** conditional blokları. Ayrıca bu blokların içinde, belirli eylemleri gerçekleştirmek için **izinleri kontrol etmek** amacıyla MACF'yi çağıran `mac_proc_check*` çağrılarını bulmak mümkündür. MACF callout'larının formatı ise şöyledir: **`mac_<object>_<opType>_opName`**.

Object aşağıdakilerden biridir: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` genellikle eyleme izin vermek veya eylemi reddetmek için kullanılan `check` değeridir. Ancak kext'in verilen eyleme tepki vermesini sağlayan `notify` değerini bulmak da mümkündür.

Bir örneği [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) adresinde bulabilirsiniz:

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Ardından, `mac_file_check_mmap` kodunu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) adresinde bulmak mümkündür.
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
Bu, kodu [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> adresinde bulunabilen `MAC_CHECK` macro'sunu çağırır.
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
Bu, kayıtlı tüm mac policy'leri dolaşarak fonksiyonlarını çağırır ve çıktıyı `error` değişkeninde depolar. Bu değişken yalnızca `mac_error_select` tarafından success kodlarıyla geçersiz kılınabilir; dolayısıyla herhangi bir kontrol başarısız olursa tüm kontrol başarısız olur ve action'a izin verilmez.

> [!TIP]
> Ancak tüm MACF callout'larının yalnızca action'ları reddetmek için kullanılmadığını unutmayın. Örneğin `mac_priv_grant`, [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) macro'sunu çağırır. Bu macro, herhangi bir policy 0 yanıtı verirse istenen privilege'i verir:
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

Bu callout'lar, [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) içinde tanımlanan onlarca **privilege**'i kontrol etmek ve sağlamak için kullanılır.\
Bazı kernel kodları, [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) içindeki `priv_check_cred()` fonksiyonunu, process'in KAuth credentials bilgileri ve privilege kodlarından biriyle çağırır. Bu fonksiyon, herhangi bir policy'nin privilege'in verilmesini **reddedip** reddetmediğini görmek için `mac_priv_check`'i çağırır; ardından herhangi bir policy'nin `privilege`'i verip vermediğini görmek için `mac_priv_grant`'i çağırır.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Bu hook, tüm system call'ları intercept etmeyi sağlar. `bsd/dev/[i386|arm]/systemcalls.c` içinde, şu kodu içeren tanımlanmış [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) fonksiyonunu görmek mümkündür:
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
Çağıran process içindeki **bitmask** değerini kontrol eder ve mevcut syscall'ın `mac_proc_check_syscall_unix` çağırması gerekip gerekmediğini belirler. Bunun nedeni, syscall'ların çok sık çağrılması ve her seferinde `mac_proc_check_syscall_unix` çağırmaktan kaçınmanın faydalı olmasıdır.

Bir process içindeki syscall bitmask'lerini ayarlayan `proc_set_syscall_filter_mask()` fonksiyonunun, sandbox'lanmış process'ler üzerinde maskeleri ayarlamak için Sandbox tarafından çağrıldığını unutmayın.

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) içinde tanımlanan bazı syscall'lar aracılığıyla MACF ile etkileşim kurmak mümkündür:
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
Offensive reversing için **`__mac_syscall`**, hâlâ en iyi userland chokepoint'lerinden biridir. **`mpo_policy_syscall`** tarafından işlenecek bir **policy name** (örneğin `"Sandbox"` veya `"AMFI"`), **policy-specific selector/code** ve **opaque argument blob** işaretçisi taşır. Bu, belgelenmemiş operasyonları önce userland üzerinden reverse etmek ve yalnızca daha sonra kernel implementasyonuna geçiş yapmak için oldukça kullanışlıdır. Sandbox genellikle buna `__sandbox_ms` üzerinden ulaşır; AMFI de dyld policy kararları için aynı mekanizmayı kullanır.<sup>[[2]](#references)[[5]](#references)</sup>

## Pratik offensive research notları

Güncel macOS bug'ları nadiren doğrudan "MACF'yi kırar". Bunun yerine genellikle bir **MACF / Sandbox / TCC kararı ile daha sonra gerçekleşen privileged action arasındaki desynchronisation** kötüye kullanılır.

### Broker path checks vs gerçek privileged action

Tekrarlanan bir pattern, privileged bir daemon'ın bir path sürümü üzerinde **userland pre-check** (örneğin `sandbox_check_by_audit_token()`) gerçekleştirmesi ve ardından gerçek privileged sink'i **farklı veya non-canonical, attacker-controlled bir path** ile çalıştırmasıdır. Güncel `diskarbitrationd` / `storagekitd` araştırmaları buna iyi bir örnektir: **directory traversal** ve **symlink swaps**, saldırganın daemon'ın sandbox validation işleminden geçmesini ve ardından `~/Library/Application Support/com.apple.TCC` gibi hassas konumların üzerine mount etmesini sağlar. Bu durum, seçilen mount point'e bağlı olarak bug'ı **sandbox escape**, **local privilege escalation** veya **TCC bypass** hâline getirir.<sup>[[6]](#references)</sup>

Sandbox'tan erişilebilen root broker'larını audit ederken önce şunlar için grep yapın:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`, helper-tool XPC methods gibi privileged sink'ler veya daha sonra attacker-controlled path'lere root olarak dokunan herhangi bir şey

### Private entitlements kullanan trusted deputies

Diğer pratik pattern, MACF hooks'larına doğrudan saldırmak yerine sınırı aşmak için gereken haklara zaten sahip bir **trusted process**'i kötüye kullanmaktır. Güncel Safari/TCC araştırmaları buna iyi bir örnektir: İlginç primitive "kernel'de TCC'yi devre dışı bırakmak" değil, **`com.apple.private.tcc.allow`** taşıyan Apple-signed bir process'in hassas işlemi sizin adınıza gerçekleştirmesini sağlayacak şekilde local policy/configuration'ı değiştirmekti.<sup>[[8]](#references)</sup> Pratikte yüksek değerli audit hedefleri, şu özellikleri birleştiren Apple daemon/app'leridir:

- **private entitlements** veya FDA-like reach
- yazılabilir bir config / database / mount point / policy file
- daha sonra **Sandbox**, **AMFI**, **TCC** veya başka bir MACF policy tarafından mediated edilen hassas bir operasyon

Daha derin product-specific reversing için [macOS Sandbox](macos-sandbox/README.md) ve [macOS TCC](macos-tcc/README.md) hakkındaki özel sayfalara bakın.

## References

- [1] [XNU — `security/mac_policy.h` (tam MACF policy operations vector'ü)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` makroları)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (`priv_check`/`priv_grant` tarafından kullanılan privilege kodları)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple Vulnerabilities'ı Ortaya Çıkarmak: diskarbitrationd ve storagekitd Audit Bölüm 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool'u](https://newosxbook.com/xxr/index.php)
- [8] [Yeni macOS vulnerability'si, "HM Surf", yetkisiz data access'e yol açabilir (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
